"""An application to launch a kernel by name in a local subprocess."""

import os
import re
import signal
import sys
import uuid
from pathlib import Path
from signal import SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1
from typing import Any, Sequence, Union

from jupyter_client import __version__  # type: ignore
from jupyter_client.kernelspec import KernelSpecManager
from jupyter_client.manager import KernelManager
from jupyter_core.application import JupyterApp, base_flags
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.iostream import StreamClosedError
from traitlets import Bool, Integer, Unicode

HELP_LEAVE = """
Launch remote kernel, leave it running, and exit this SSHKernelApp.
When set to True, it provides a way to skip having to interact with the
SSHKernelApp using keyboard input or signals.
"""


class SSHKernelApp(JupyterApp):
    """Launch a kernel by its local name."""

    version = __version__
    description = """
    Launch a kernel by its local name. You can pass extra arguments to the
    SSHProvisioner, e.g., `--SSHProvisioner.persistent=True`,
    `--SSHProvisioner.persistent_file=/path/to/sshpyk_kernel.json` or
    `--SSHProvisioner.existing=/path/to/sshpyk_kernel.json`. Please see the provisioner
    source code for configurable options. Due to technical limitations these options
    will not be displayed when running `sshpyk-kernel --help-all`.
    """

    classes = [KernelManager, KernelSpecManager]
    aliases = {
        "kernel": "SSHKernelApp.kernel_name",
        "leave": "SSHKernelApp.leave",
    }
    flags = {
        "debug": base_flags["debug"],
        # To not have to pass `--leave=True`, but just `--leave`
        "leave": ({"SSHKernelApp": {"leave": True}}, HELP_LEAVE),
    }

    kernel_name = Unicode(
        config=True,
        help="The name of a kernel type to start",
        allow_none=False,
    )
    capture_stdin = Bool(
        True,
        config=True,
        help="Enable handling of Ctrl+D to interrupt/shutdown/restart/leave."
        "This has no effect in a non-interactive terminal.",
    )
    poll_interval = Integer(
        5000,
        config=True,
        help="Interval in milliseconds for polling to ensure SSH tunnels are running",
    )
    leave = Bool(
        False,
        config=True,
        help=HELP_LEAVE,
    )

    def initialize(self, argv: Union[str, Sequence[str], None] = None) -> None:
        """Initialize the application."""
        super().initialize(argv)

        cf_basename = f"kernel-{uuid.uuid4()}.json"
        fp = os.path.join(self.runtime_dir, cf_basename)
        self.config.setdefault("KernelManager", {}).setdefault("connection_file", fp)
        self.km = KernelManager(kernel_name=self.kernel_name, config=self.config)

        self.loop = IOLoop.current()

        # Setup periodic callback to ensure tunnels are running even if internet
        # connection is lost.
        # If the callback runs for longer than callback_time milliseconds,
        # subsequent invocations will be skipped to get back on schedule.
        self.periodic_poll = PeriodicCallback(self.poll, self.poll_interval)

        # Setup stdin handler to detect Ctrl+D (EOF) in an interactive terminal
        if self.capture_stdin and sys.stdin.isatty():
            self.log.debug("Setting up stdin listener for Ctrl+D")
            self.loop.add_handler(
                sys.stdin.fileno(), self._handle_stdin, self.loop.READ
            )

    def _handle_stdin(self, fd: int, events: int) -> None:
        """Handle stdin input, checking for EOF (Ctrl+D)"""
        try:
            data = os.read(fd, 1)
            if not data:  # EOF detected
                self.log.info("Received EOF (Ctrl+D)")
                sys.stdout.write(
                    "Pick an action and press Enter: "
                    "Y = shutdown (default), i = interrupt, "
                    "l = leave w/out kernel shutdown, r = restart, n = nothing"
                    "\nAction? [Y/i/l/r/n]: "
                )
                sys.stdout.flush()

                # Temporarily remove handler to avoid recursion
                self.loop.remove_handler(fd)

                response = sys.stdin.readline().strip().lower()
                if response == "" or response == "y":
                    self.shutdown(0)
                elif response == "l":
                    self.leave_app(0)
                elif response == "r":
                    self.restart(0)
                elif response == "i":
                    self.interrupt(0)
                else:
                    self.log.info("No actions taken, resuming")

                # Restore handler
                self.loop.add_handler(fd, self._handle_stdin, self.loop.READ)
        except (OSError, StreamClosedError):
            # Stream closed, remove the handler
            self.loop.remove_handler(fd)

    def setup_signals(self) -> None:
        """Set up signal handlers.

        SIGINT (Ctrl-C) will interrupt the kernel rather than shutdown
        SIGTERM will shutdown the remote kernel and all local and remote processes
        """
        if os.name == "nt":
            return

        self.log.info("Setting up signal handlers")

        def shutdown_handler(signo: int, frame: Any) -> None:
            if signo == SIGINT:
                self.loop.add_callback_from_signal(self.interrupt, signo)
            elif signo == SIGUSR1:
                self.loop.add_callback_from_signal(self.restart, signo)
            elif signo == SIGQUIT:
                self.loop.add_callback_from_signal(self.leave_app, signo)
            elif signo == SIGTERM:
                self.log.info(f"Shutting down on signal {signo}")
                self.loop.add_callback_from_signal(self.shutdown, signo)
            else:
                self.log.debug(f"Unexpected signal {signo}")

        c = self.__class__.__name__
        for sig, msg in (
            (SIGHUP, "to shutdown the kernel"),
            (SIGTERM, "to shutdown the kernel"),
            (SIGINT, "or press Ctrl+C to interrupt the kernel"),
            (SIGUSR1, "to restart the kernel"),
            (
                SIGQUIT,
                f"or press Ctrl+\\ to quit this {c} without shutting down the kernel",
            ),
        ):
            signal.signal(sig, shutdown_handler)
            self.log.info(f"You can send {sig!r} {msg}")

        self.log.info(
            "You can press Ctrl+D and execute one of these actions: "
            "interrupt, shutdown, restart or leave (without shutdown)"
        )

    def interrupt(self, signo: int) -> None:
        """Interrupt the kernel."""
        msg = f"Interrupting kernel on signal {signo}"
        if signo == 0:
            msg = "Interrupting kernel on Ctrl+D"
        self.log.info(msg)
        self.km.interrupt_kernel()

    def shutdown(self, signo: int) -> None:
        """Shut down the application."""
        self.periodic_poll.stop()
        msg = f"Shutting down on signal {signo}"
        if signo == 0:
            msg = "Shutting down on Ctrl+D"
        elif signo == -1:
            msg = None
        if msg:
            self.log.info(msg)
        self.km.shutdown_kernel()
        p = getattr(self.km, "provisioner", None)
        if p:
            fp = getattr(p, "persistent_file", None)
            if fp:
                Path(fp).unlink()
                self.log.info(f"Persistent info file {fp} removed")
        self.loop.stop()

    def leave_app(self, signo: int) -> None:
        """Leave the application without shutting down the kernel."""
        c = self.__class__.__name__
        msg = f"Leaving {c} on signal {signo}. Remote kernel will not be shutdown!"
        if signo == 0:
            msg = "Leaving on Ctrl+D. Remote kernel will not be shutdown!"
        elif signo == -1:
            msg = "Leaving after kernel launch. Remote kernel will not be shutdown!"
        self.log.info(msg)
        is_alive = self.km.is_alive()  # calls provisioner.poll()
        if not is_alive:
            self.log.error("Kernel is not running anymore!")
            self.shutdown(signo)
        else:
            # Make the SSHProvisioner forget about the remote kernel
            p = getattr(self.km, "provisioner", None)
            if p:
                pid = getattr(p, "rem_pid_k", None)
                if pid:
                    self.log.info(f"Remote kernel RPID={pid} not killed")
                    p.rem_pid_k = None
                pid = getattr(p, "rem_pid_ka", None)
                if pid:
                    self.log.info(f"Remote SSHKernelApp RPID={pid} not killed")
                    p.rem_pid_ka = None
            self.loop.stop()

    def restart(self, signo: int) -> None:
        """Restart the kernel."""
        msg = f"Restarting kernel on signal {signo}"
        if signo == 0:
            msg = "Restarting kernel on Ctrl+D"
        self.log.info(msg)
        self.km.restart_kernel()

    async def poll(self) -> None:
        """Ensure the ssh tunnels are running."""
        if not self.km.shutting_down:
            p = getattr(self.km, "provisioner", None)
            if p:
                # restart SSH tunnels (if not shutting down)
                ret = await p.poll()
                if ret is not None:
                    self.log.info(f"Kernel quit with exit code {ret}, shutting down.")
                    self.shutdown(-1)

    def log_connection_info(self) -> None:
        """Log the connection info for the kernel."""
        cf = self.km.connection_file
        self.log.info(f"Connection file: {cf}")
        self.log.info(f"To connect a client: --existing {os.path.basename(cf)}")

    def start(self) -> None:
        """Start the application."""
        self.log.info(f"Starting kernel {self.kernel_name}")
        try:
            self.km.start_kernel()
            self.setup_signals()
            self.log_connection_info()
            p = getattr(self.km, "provisioner", None)
            if p and getattr(p, "persistent", False):
                p.write_persistent_info()
            # Start the tunnel checker
            self.periodic_poll.start()
            self.loop.start()
            if self.leave:
                self.leave_app(0)
        finally:
            if hasattr(self, "periodic_poll"):
                self.periodic_poll.stop()
            self.km.cleanup_resources()


main = SSHKernelApp.launch_instance

# This is mainly to allow running the SSHKernelApp as a script on the remote machine
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\.pyw|\.exe)?$", "", sys.argv[0])
    sys.exit(main())
