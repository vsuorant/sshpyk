"""An application to launch a kernel by name in a local subprocess."""

import os
import signal
import typing as t
import uuid
from signal import SIGCHLD, SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2

from jupyter_client import __version__
from jupyter_client.kernelspec import NATIVE_KERNEL_NAME, KernelSpecManager
from jupyter_client.manager import KernelManager
from jupyter_core.application import JupyterApp, base_flags
from tornado.ioloop import IOLoop
from traitlets import Unicode


class SSHKernelApp(JupyterApp):
    """Launch a kernel by its local name."""

    version = __version__
    description = "Launch a kernel by its local name."

    classes = [KernelManager, KernelSpecManager]

    flags = {"debug": base_flags["debug"]}

    kernel_name = Unicode(
        config=True,
        default_value=NATIVE_KERNEL_NAME,
        help="The name of a kernel type to start",
    )

    def initialize(self, argv: t.Union[str, t.Sequence[str], None] = None) -> None:
        """Initialize the application."""
        super().initialize(argv)

        cf_basename = f"kernel-{uuid.uuid4()}.json"
        fp = os.path.join(self.runtime_dir, cf_basename)
        self.config.setdefault("KernelManager", {}).setdefault("connection_file", fp)
        self.km = KernelManager(kernel_name=self.kernel_name, config=self.config)

        self.loop = IOLoop.current()

    def setup_signals(self) -> None:
        """Set up signal handlers.

        SIGINT (Ctrl-C) will interrupt the kernel rather than shutdown
        SIGTERM will shutdown the remote kernel and all local and remote processes
        """
        if os.name == "nt":
            return

        self.log.info("Setting up signal handlers")
        self.log.info(f"{getattr(self, 'restart', None)=}")

        def shutdown_handler(signo: int, frame: t.Any) -> None:
            if signo == SIGINT:
                self.loop.add_callback_from_signal(self.interrupt, signo)
            elif signo == SIGUSR1:
                self.loop.add_callback_from_signal(self.restart, signo)
            elif signo == SIGUSR2:
                self.loop.add_callback_from_signal(self.leave, signo)
            elif signo == SIGCHLD:
                self.loop.add_callback_from_signal(self.restart_tunnels, signo)
            else:
                self.log.info(f"Shutting down on signal {signo}")
                self.loop.add_callback_from_signal(self.shutdown, signo)

        c = self.__class__.__name__
        for sig, msg in (
            (SIGHUP, "to shutdown the kernel"),
            (SIGTERM, "to shutdown the kernel"),
            (SIGQUIT, "or press Ctrl+\\ to shutdown the kernel"),
            (SIGINT, "or press Ctrl+C to interrupt the kernel"),
            (SIGUSR1, "to restart the kernel"),
            (SIGUSR2, f"to exit this {c} without shutting down the kernel"),
        ):
            signal.signal(sig, shutdown_handler)
            self.log.info(f"You can send {sig!r} {msg}")

        # Handle SIGCHLD signal which is sent when a child process terminates.
        # We use this signal to be able to restart the ssh tunnels when they die,
        # which can happen on internet connection loss.
        signal.signal(signal.SIGCHLD, shutdown_handler)
        # Avoid SIGCHLD to potentially interfere with other operations
        signal.siginterrupt(signal.SIGCHLD, False)

    def interrupt(self, signo: int) -> None:
        """Interrupt the kernel."""
        self.log.info(f"Interrupting kernel on signal {signo}")
        self.km.interrupt_kernel()

    def shutdown(self, signo: int) -> None:
        """Shut down the application."""
        self.log.info(f"Shutting down on signal {signo}")
        self.km.shutdown_kernel()
        self.loop.stop()

    def leave(self, signo: int) -> None:
        """Leave the application without shutting down the kernel."""
        c = self.__class__.__name__
        msg = f"Leaving {c} on signal {signo}. Remote kernel will not be shutdown!"
        self.log.info(msg)
        is_alive = self.km.is_alive()  # calls provisioner.poll()
        if not is_alive:
            self.log.error("Kernel is not running anymore!")
            self.shutdown(signo)
        else:
            # Make the provisioner forget about the remote kernel
            p = self.km.provisioner
            if p.rem_pid_k:
                self.log.info(f"Remote kernel RPID={p.rem_pid_k} not killed")
                p.rem_pid_k = None
            if p.rem_pid_ka:
                self.log.info(f"Remote KernelApp RPID={p.rem_pid_ka} not killed")
                p.rem_pid_ka = None
            self.loop.stop()

    def restart(self, signo: int) -> None:
        """Restart the kernel."""
        self.log.info(f"Restarting kernel on signal {signo}")

    def restart_tunnels(self, signo: int) -> None:
        """
        Handle SIGCHLD signal which is sent when a child process terminates.
        Depending on the unix flavour this signal might be sent as well when a child
        process is stopped/continued. In principle this should not apply to our
        ssh tunnels processes.
        """
        self.log.debug(f"SIGCHLD received on signal {signo}")
        ripped = False
        while True:
            try:
                pid = self.km.provisioner.pid_kernel_tunnels or -1
                # Reap the zombie process, this is the way to make the os stop spamming
                # us with SIGCHLD signals.
                # ! We might still get multiple SIGCHLD signals in a row for the same
                # ! dead process.
                pid, status = os.waitpid(pid, os.WNOHANG)
                if pid == 0:
                    self.log.debug("No zombie processes to reap")
                    break
                self.log.debug(f"Reaped process {pid} with status {status}")
                ripped = True
            except ChildProcessError as e:
                self.log.debug(f"{e}")
                break
            except OSError as e:
                ec = e.__class__.__name__
                self.log.debug(f"Unexpected error: {ec}: {e}")
                break

        if ripped and not self.km.shutting_down:
            # calls provisioner.poll() which will restart SSH tunnels if these are dead
            self.km.is_alive()

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
            self.loop.start()
        finally:
            self.km.cleanup_resources()


main = SSHKernelApp.launch_instance
