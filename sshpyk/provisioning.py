"""SSH Kernel Provisioner implementation for Jupyter Client."""

import asyncio
import json
import os
import re
import selectors
import subprocess
from pathlib import Path
from shutil import which
from subprocess import PIPE, STDOUT, Popen, run
from typing import Any, Dict, List, Optional

from jupyter_client.connect import KernelConnectionInfo, LocalPortCache
from jupyter_client.provisioning.provisioner_base import KernelProvisionerBase
from traitlets import Unicode


def _nope(*args, **kwargs):
    pass


getpgid = getattr(os, "getpgid", _nope)


class ASCII(Unicode):
    def validate(self, obj, value):
        value = super().validate(obj, value)
        try:
            value.encode("ascii")
            return value
        except UnicodeEncodeError:
            self.error(obj, value)


class UnicodePath(Unicode):
    def validate(self, obj, value):
        value = super().validate(obj, value)
        try:
            Path(value)  # should raise if not a valid path
            return value
        except:
            self.error(obj, value)
            raise


class SSHKernelProvisioner(KernelProvisionerBase):
    """
    Kernel provisioner that launches Jupyter kernels on remote systems via SSH.

    This provisioner connects to remote systems using SSH, sets up port local forwarding
    for kernel communication, and manages the lifecycle of the remote kernel.
    """

    ssh_host = ASCII(
        config=True,
        help="Remote host to connect to",
        allow_none=False,
    )
    remote_python_prefix = UnicodePath(
        config=True,
        help="Path to Python prefix on remote system. "
        + "Run `python -c 'import sys; print(sys.prefix)'` on the remote system "
        + "to find the path. If the remote kernel is part of a virtual environment, "
        + "first activate your virtual environment and then query the `sys.prefix`. "
        + "It must have jupyter_client package installed.",
        allow_none=False,
    )
    remote_kernel_name = UnicodePath(
        config=True,
        help="Kernel name on the remote system "
        + "(i.e. first column of `jupyter kernelspec list` on the remote system).",
        allow_none=False,
    )

    process = None
    process_tunnels = None

    ports_cached = False
    ssh = None

    rem_python = None
    rem_jupyter = None
    rem_conn_fp = None
    rem_conn_info = None

    pid = None
    pgid = None
    pid_tunnels = None
    pgid_tunnels = None

    # Use asyncio to read output with timeout
    async def extract_connection_file_from_process_pipes(self) -> Optional[str]:
        """
        When executing the `jupyter kernel --kernel=...` it prints:
        ```
        [KernelApp] Starting kernel 'python3'
        [KernelApp] Connection file: /some/path/to/the/connection_file.json
        [KernelApp] To connect a client: --existing connection_file.json
        """
        # Create a selector and register both stdout and stderr pipes to listen events
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")

        while True:
            await asyncio.sleep(0.1)  # yield control back to event loop

            # Check for available data on either pipe
            events = selector.select(timeout=0)
            for key, _ in events:
                pipe_name, pipe = key.data, key.fileobj

                line = pipe.readline()
                if not line:  # EOF on this pipe
                    self.log.error(f"Process {pipe_name} closed unexpectedly")
                    selector.unregister(pipe)
                    continue

                line_str = line.decode().strip()
                if line_str:
                    # Log both stdout and stderr
                    self.log.info(f"Remote jupyter {pipe_name}: {line_str}")
                    # Then information was output into the stderr, but check both
                    match = re.search(r"file: (.*\.json)", line_str)
                    if match:
                        return match.group(1)

            # If no pipes left to monitor or process ended, exit loop
            if not selector.get_map() or self.process.poll() is not None:
                break

    async def extract_connection_file(self, rem_cmd: str, timeout: int = 30) -> str:
        self.log.debug(
            f"Waiting for remote connection file path from {rem_cmd!r} ({timeout = })"
        )
        try:
            rcf = await asyncio.wait_for(
                self.extract_connection_file_from_process_pipes(), timeout=timeout
            )
        except asyncio.TimeoutError as e:
            msg = f"Timed out ({timeout}s) waiting for connection file information"
            self.log.error(msg)
            self.log.exception(e)
            raise RuntimeError(msg) from e

        if not rcf:
            msg = f"Could not extract connection file path on remote from {rem_cmd!r}"
            self.log.error(msg)
            raise RuntimeError(msg)

        try:
            Path(rcf)  # should raise if not valid
        except Exception as e:
            msg = f"Unexpected remote connection file path {rcf}."
            self.log.error(msg)
            raise RuntimeError(msg) from e

        self.log.info(f"Connection file path on remote: {rcf}")
        return rcf

    def fetch_remote_connection_info(self) -> Dict[str, Any]:
        try:
            result = run(  # noqa: S603
                [self.ssh, "-q", self.ssh_host, f"cat {self.rem_conn_fp!r}"],
                stdout=PIPE,
                stderr=STDOUT,
                check=True,
            )
            rci = json.loads(result.stdout)
            rci["key"] = rci["key"].encode()  # the rest of the code uses bytes
            return rci
        except json.JSONDecodeError as e:
            self.log.exception(e)
            msg = f"Failed to parse remote connection file: {e}"
            self.log.error(msg)
            raise RuntimeError(msg) from e
        except subprocess.CalledProcessError as e:
            self.log.exception(e)
            msg = f"Failed to fetch remote connection file: {e}"
            self.log.error(msg)
            raise RuntimeError(msg) from e

    async def pre_launch(self, **kwargs: Any) -> Dict[str, Any]:
        """Prepare for kernel launch."""
        if (
            not self.ssh_host
            or not self.remote_python_prefix
            or not self.remote_kernel_name
        ):
            raise ValueError("Bad configuration")

        self.rem_python = str(Path(self.remote_python_prefix) / "bin" / "python")
        self.rem_jupyter = str(Path(self.remote_python_prefix) / "bin" / "jupyter")

        self.ssh = which("ssh")
        if not self.ssh:
            raise EnvironmentError("'ssh' executable not found")

        km = self.parent  # KernelManager
        if km is None:
            raise RuntimeError("Parent kernel manager not set")

        rem_args = [
            self.rem_jupyter,
            "kernel",
            f"--kernel={self.remote_kernel_name}",
            # This did not work well because the jupyter command on the remote seemed to
            # override the connection ports in the connection file.
            # Better to not interfere with the launch of the remote kernel. Let it take
            # care of everything as configured on the remote system.
            # f"--KernelManager.connection_file='{self.rem_conn_fp}'",
        ]
        rem_cmd = " ".join(rem_args)
        cmd = [
            self.ssh,
            "-q",  # mute ssh output
            # Allocate a pseudo-tty.
            # Without this the remote kernel processes stays in 'Z' (zombie) mode when
            # the client (e.g. JupyterLab) instructs the kernel to shutdown.
            "-t",
            self.ssh_host,
            # `exec` used to have less remote processes
            f"exec {rem_cmd}",
        ]
        self.process = Popen(cmd, stdout=PIPE, stderr=PIPE)  # noqa: S603

        self.pid = self.process.pid
        self.pgid = None
        try:
            self.pgid = getpgid(self.pid)
        except OSError:
            pass

        self.rem_conn_fp = await self.extract_connection_file(rem_cmd, timeout=30)

        rci = self.rem_conn_info = self.fetch_remote_connection_info()

        # This part is inspired from LocalProvisioner.pre_launch where it seems to be
        # a temporary thing because the division of labor is not clear.
        if km.cache_ports and not self.ports_cached:
            # Find available ports on local machine for all channels.
            # These are the ports that the local kernel client will connect to.
            # These ports are SSH-forwarded to the remote kernel.
            lpc = LocalPortCache.instance()
            km.shell_port = lpc.find_available_port(km.ip)
            km.iopub_port = lpc.find_available_port(km.ip)
            km.stdin_port = lpc.find_available_port(km.ip)
            km.hb_port = lpc.find_available_port(km.ip)
            km.control_port = lpc.find_available_port(km.ip)
            self.ports_cached = True

        # Fill in the rest of the connection info based on the remote connection info
        km.transport = rci["transport"]
        km.session.signature_scheme = rci["signature_scheme"]
        km.session.key = rci["key"]
        km.session.kernel_name = rci.get("kernel_name", "")

        _ = kwargs.pop("extra_arguments", [])  # bc LocalProvisioner does it

        # if-else bc LocalProvisioner does it
        if "env" in kwargs:
            jupyter_session = kwargs["env"].get("JPY_SESSION_NAME", "")
            km.write_connection_file(jupyter_session=jupyter_session)
        else:
            km.write_connection_file()

        ci = self.connection_info = km.get_connection_info()

        # SSH tunnels between local and remote ports
        ssh_tunnels = []
        for key in rci:
            if key.endswith("_port"):
                ssh_tunnels += ["-L", f"{ci[key]}:localhost:{rci[key]}"]

        cmd = [
            self.ssh,
            "-q",  # mute ssh output
            "-N",  # do nothing, i.e. maintain the tunnels alive
            *ssh_tunnels,  # ssh tunnels within the same command
            self.ssh_host,
        ]

        # NOTE: in case of future bugs check if calling this is relevant
        # cmd = km.format_kernel_cmd(extra_arguments=extra_arguments)

        # NB `cmd` arg is expected inside the KernelManager
        return await super().pre_launch(cmd=cmd, **kwargs)

    async def launch_kernel(
        self, cmd: List[str], **kwargs: Any
    ) -> KernelConnectionInfo:
        """Launch a kernel on the remote system via SSH."""
        self.log.debug(f"Connection info remote: {self.rem_conn_info}")
        self.log.debug(f"Connection info local: {self.connection_info}")
        cmd_str = " ".join(cmd)
        self.log.info(f"SSH-forwarding local ports to remote kernel ports: {cmd_str!r}")
        self.process_tunnels = Popen(cmd, stdout=None, stderr=None)  # noqa: S603

        self.pid_tunnels = self.process_tunnels.pid
        self.pgid_tunnels = None
        try:
            self.pgid = getpgid(self.pid_tunnels)
        except OSError:
            pass

        return self.connection_info

    async def get_provisioner_info(self) -> Dict:
        """Get information about this provisioner instance."""
        provisioner_info = await super().get_provisioner_info()
        provisioner_info.update(
            {
                "ssh_host": self.ssh_host,
                "remote_python_prefix": self.remote_python_prefix,
                "remote_kernel_name": self.remote_kernel_name,
                "pid": self.pid,
                "pgid": self.pgid,
                "pid_tunnels": self.pid_tunnels,
                "pgid_tunnels": self.pgid_tunnels,
                "rem_conn_fp": self.rem_conn_fp,
                "rem_conn_info": self.rem_conn_info,
            }
        )
        return provisioner_info

    async def load_provisioner_info(self, provisioner_info: Dict) -> None:
        """Load information about this provisioner instance."""
        await super().load_provisioner_info(provisioner_info)
        self.ssh_host = provisioner_info["ssh_host"]
        self.remote_python_prefix = provisioner_info["remote_python_prefix"]
        self.remote_kernel_name = provisioner_info["remote_kernel_name"]
        self.pid = provisioner_info["pid"]
        self.pgid = provisioner_info["pgid"]
        self.pid_tunnels = provisioner_info["pid_tunnels"]
        self.pgid_tunnels = provisioner_info["pgid_tunnels"]
        self.rem_conn_fp = provisioner_info["rem_conn_fp"]
        self.rem_conn_info = provisioner_info["rem_conn_info"]

    async def cleanup(self, restart: bool = False) -> None:
        """Clean up resources used by the provisioner."""
        # Return cached ports if we're not restarting
        if self.ports_cached and not restart:
            lpc = LocalPortCache.instance()
            for k, port in self.connection_info.items():
                if k.endswith("_port"):
                    lpc.return_port(port)
            self.ports_cached = False

        # TODO: kill remote jupyter process which should remove the connection file
        # automatically

    @property
    def has_process(self) -> bool:
        """Returns true if this provisioner is currently managing a process."""
        return self.process is not None

    async def poll(self) -> Optional[int]:
        """Checks if kernel process is still running."""
        if self.process:
            return self.process.poll()
        return 0

    async def _wait(self, process: Popen):
        if not self.process:
            return 0
        # Wait for process to terminate
        while await self.poll() is None:
            await asyncio.sleep(0.1)

        # Process is no longer alive, wait and clear
        ret = self.process.wait()
        # Close file descriptors
        for attr in ["stdout", "stderr", "stdin"]:
            fid = getattr(self.process, attr)
            if fid:
                fid.close()
        self.process = None
        return ret

    async def wait(self) -> Optional[int]:
        """Waits for processes to terminate."""
        ret0, ret1 = await asyncio.gather(
            self._wait(self.process),
            self._wait(self.process_tunnels),
        )
        return ret0 or ret1

    async def send_signal(self, signum: int) -> None:
        """Sends signal identified by signum to the kernel process."""
        # TODO: should this be handled somehow differently?
        if self.process:
            self.process.send_signal(signum)

    async def kill(self, restart: bool = False) -> None:
        """Kill the kernel process."""
        for p in (self.process, self.process_tunnels):
            if p:
                p.kill()

    async def terminate(self, restart: bool = False) -> None:
        """Terminates the kernel process."""
        for p in (self.process, self.process_tunnels):
            if p:
                p.terminate()
