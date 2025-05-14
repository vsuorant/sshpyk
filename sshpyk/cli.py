"""Command line interface to manage sshpyk kernel specifications."""

import argparse
import json
import logging
import sys
from pathlib import Path

from jupyter_client.kernelspec import KernelSpecManager

from .provisioning import RGX_KERNEL_NAME, RGX_SSH_HOST_ALIAS
from .utils import (
    DEFAULT_REMOTE_SCRIPT_DIR,
    LAUNCH_TIMEOUT,
    SHUTDOWN_TIME,
    get_local_ssh_configs,
    remote_checks,
    validate_ssh_config,
    verify_local_ssh,
)

try:
    from .__version__ import __version__  # type: ignore
except ImportError:
    __version__ = "0.0"

logger = logging.getLogger(__name__)

LOG_FORMAT = "%(process)6d %(asctime)s %(levelname)-8s %(name)s %(module)s:%(lineno)d %(funcName)s: %(message)s"  # noqa: E501

# ANSI color codes for terminal output
G = "\033[32m"  # Green
R = "\033[31m"  # Red
C = "\033[36m"  # Cyan
M = "\033[35m"  # Magenta
E = "\033[90m"  # Grey
W = "\033[33m"  # Orange
N = "\033[39m"  # Reset color only, not formatting


K_NAME = "Name:"
K_DISP = "Display Name:"
K_RES = "Resource Dir:"
K_SPEC = "Kernel spec:"
K_CMD = "Command:"
K_CMDS = "Command (simplified):"
K_LANG = "Language:"
K_SSH = "SSH Host Alias:"
K_CONN = "SSH Connection:"
K_SSH_PATH = "SSH Path:"
K_EXE = "Remote Python:"
K_RKER = "Remote Kernel Name:"
K_RLANG = "Remote Language:"
K_TIME = "Launch Timeout:"
K_TIME_SD = "Shutdown Timeout:"
K_RCMD = "Remote Command:"
K_INT = "Interrupt Mode:"
K_RINT = "Remote Interrupt Mode:"
K_RRES = "Remote Resource Dir:"
K_RUNAME = "Remote System:"
K_RSD = "Remote Script Dir:"

ALL_KEYS = [
    K_NAME,
    K_DISP,
    K_RES,
    K_SPEC,
    K_CMD,
    K_CMDS,
    K_LANG,
    K_SSH,
    K_SSH_PATH,
    K_RUNAME,
    K_EXE,
    K_RKER,
    K_RLANG,
    K_TIME,
    K_TIME_SD,
    K_RCMD,
    K_INT,
    K_RINT,
    K_RRES,
    K_RSD,
]

# Global variable for maximum key length
K_LEN = max(len(key) for key in ALL_KEYS)


def create_header(text: str, color: str = "") -> str:
    dash_count = K_LEN - len(text)
    left_dashes = "-" * (dash_count // 2)
    right_dashes = "-" * (dash_count - (dash_count // 2))
    return f"{color}{left_dashes}{text}{right_dashes}{N if color else ''}"


def list_kernels(args: argparse.Namespace) -> None:
    """List all available kernels with sanity checks for SSH kernels."""
    # reset color upfront to avoid default color change after our color resets
    print(f"{N}", end="")
    specs = KernelSpecManager().get_all_specs()

    if not specs:
        print("No kernels available")
        return

    # Separate kernels into local and SSH
    local_kernels, ssh_kernels = separate_kernels(specs)

    # Print local kernels
    if local_kernels and (args.local or not (args.remote and not args.local)):
        print_local_kernels(local_kernels, specs)

    # Process SSH kernels with sanity checks
    if ssh_kernels and (args.remote or not (args.local and not args.remote)):
        print_ssh_kernels(ssh_kernels, args.no_check)


def separate_kernels(specs):
    """Separate kernels into local and SSH categories."""
    local_kernels = []
    ssh_kernels = []

    for name, spec_info in sorted(specs.items()):
        spec = spec_info.get("spec", {})
        display_name = spec.get("display_name", "")
        resource_dir = spec_info.get("resource_dir", "")
        argv = " ".join(spec.get("argv", []))
        language = spec.get("language", "")
        interrupt_mode = spec.get("interrupt_mode", "signal")

        # Check if it's an SSH kernel
        metadata = spec.get("metadata", {})
        provisioner = metadata.get("kernel_provisioner", {})
        is_ssh = provisioner.get("provisioner_name") == "sshpyk-provisioner"

        if is_ssh:
            ssh_kernels.append(
                extract_ssh_kernel_info(
                    name,
                    spec_info,
                    display_name,
                    resource_dir,
                    language,
                    interrupt_mode,
                )
            )
        else:
            local_kernels.append(
                {
                    "name": name,
                    "display_name": display_name,
                    "resource_dir": resource_dir,
                    "argv": argv,
                    "language": language,
                    "interrupt_mode": interrupt_mode,
                }
            )

    return local_kernels, ssh_kernels


def extract_ssh_kernel_info(
    name, spec_info, display_name, resource_dir, language, interrupt_mode
):
    """Extract SSH kernel information from a kernel spec."""
    spec = spec_info.get("spec", {})
    metadata = spec.get("metadata", {})
    provisioner = metadata.get("kernel_provisioner", {})
    config = provisioner.get("config", {})

    return {
        "name": name,
        "display_name": display_name,
        "resource_dir": resource_dir,
        "language": language,
        "host": config.get("ssh_host_alias", ""),
        "remote_python": config.get("remote_python", ""),
        "remote_kernel_name": config.get("remote_kernel_name", ""),
        "launch_timeout": config.get("launch_timeout", LAUNCH_TIMEOUT),
        "shutdown_timeout": config.get("shutdown_timeout", SHUTDOWN_TIME),
        "interrupt_mode": interrupt_mode,
        "ssh": config.get("ssh", None),
        "remote_script_dir": config.get("remote_script_dir", DEFAULT_REMOTE_SCRIPT_DIR),
    }


def print_local_kernels(local_kernels, specs):
    """Print information about local kernels."""
    for kernel in local_kernels:
        # Print header for local kernels
        print(create_header(" Local Kernel ", M))

        k_lines = []
        k_lines.append(f"{M}{K_NAME:<{K_LEN}}{N} {kernel['name']}")
        k_lines.append(f"{M}{K_DISP:<{K_LEN}}{N} {kernel['display_name']}")
        k_lines.append(f"{M}{K_RES:<{K_LEN}}{N} {kernel['resource_dir']}")
        k_lines.append(f"{M}{K_CMD:<{K_LEN}}{N} {kernel['argv']}")
        k_lines.append(f"{M}{K_LANG:<{K_LEN}}{N} {kernel.get('language', '')}")
        # interrupt_mode defaults to "signal" if not specified
        k_lines.append(
            f"{M}{K_INT:<{K_LEN}}{N} {kernel.get('interrupt_mode', 'signal')}"
        )

        print("\n".join(k_lines), end="\n\n")


def print_ssh_kernels(ssh_kernels, skip_checks):
    """Print information about SSH kernels with optional sanity checks."""
    # Cache for remote kernel specs to avoid multiple calls to the same host
    remote_specs_cache = {}

    for kernel in ssh_kernels:
        # Print header for SSH kernels
        k_lines = [create_header(" SSH Kernel ", C)]

        # Perform checks if not skipped
        check_res = perform_kernel_checks(kernel, skip_checks, remote_specs_cache)

        # Format and add kernel information to lines
        format_ssh_kernel_info(k_lines, kernel, check_res)

        print("\n".join(k_lines), end="\n\n")


def perform_kernel_checks(kernel, skip_checks, remote_specs_cache):
    """Perform sanity checks on SSH kernel configuration."""
    results = {
        "remote_cmd": "",
        "ssh_path": "",
        "ssh_ok": None,
        "exec_ok": None,
        "kernel_ok": None,
        "ssh_exec_ok": None,
        "uname": None,
        "interrupt_mode_ok": kernel.get("interrupt_mode") == "message",
        "interrupt_mode_remote": None,
        "ssh_configs_val": None,
        "rsd_ok": None,
        "script_dir": None,  # as echoed on remote
    }
    try:
        ssh_bin = verify_local_ssh(kernel.get("ssh", None), name="ssh")
        results["ssh_path"] = ssh_bin
        results["ssh_exec_ok"] = ssh_bin is not None
    except Exception as e:
        results["ssh_exec_ok"] = False
        logger.error(f"Error verifying local ssh: {e}")
        results["ssh_ok"] = False
        return results

    if ssh_bin:
        configs = get_local_ssh_configs(ssh_bin, kernel["host"])
        results["ssh_configs_val"] = {
            config["host"]: validate_ssh_config(config) for config in configs
        }
    else:  # Should be caught by ssh_exec_ok = False from try-except block
        logger.warning(
            f"Local SSH not usable for kernel '{kernel['name']}' on host "
            f"'{kernel['host']}', skipping remote checks."
        )
        results["ssh_ok"] = False  # Mark connection as not OK
        return results

    if skip_checks:
        return results

    # If local SSH executable is not okay, we can't perform remote checks.
    if not results.get("ssh_exec_ok"):
        logger.warning(
            f"Local SSH not usable for host {kernel['host']}, skipping remote checks."
        )
        results["ssh_ok"] = False
        results["exec_ok"] = False
        results["kernel_ok"] = False
        results["rsd_ok"] = False
        return results

    try:
        remote_python = kernel["remote_python"]
        remote_script_dir = kernel["remote_script_dir"]
        host_alias = kernel["host"]

        # Use a cache key that represents this specific set of checks for this host
        # to avoid redundant calls if multiple kernels share the same host and config.
        cache_key = (host_alias, remote_python, remote_script_dir)

        if cache_key in remote_specs_cache:
            check_data = remote_specs_cache[cache_key]
            logger.debug(f"Using cached remote checks for {host_alias}")
        else:
            logger.debug(f"Performing remote checks for {host_alias}")
            check_data = remote_checks(
                ssh_bin,
                host_alias,
                remote_python,
                remote_script_dir,
                log=logger,  # Pass logger for consistent logging
                lp=f"[{kernel['name']}] ",  # Log prefix for context
            )
            remote_specs_cache[cache_key] = check_data

        # Process the results from check_data
        if check_data.get("err_msg") and not check_data.get("uname"):
            # This indicates a significant failure in the SSH command itself
            # or initial connection.
            results["ssh_ok"] = False
            return results

        results["uname"] = check_data.get("uname")
        results["ssh_ok"] = bool(results["uname"])

        if not results["ssh_ok"]:
            logger.debug(
                f"SSH connection to {host_alias} failed. "
                f"Error: '{check_data.get('err_msg', '')}'. "
            )
            # If basic SSH connectivity (indicated by uname) failed, reset
            results["exec_ok"] = None
            results["kernel_ok"] = None
            results["rsd_ok"] = None
            return results

        results["exec_ok"] = check_data.get("python_exec_ok")
        results["rsd_ok"] = check_data.get("script_dir_ok")
        results["script_dir"] = check_data.get("script_dir")

        remote_specs = check_data.get("remote_specs", {})

        if kernel["remote_kernel_name"] in remote_specs:
            results["kernel_ok"] = True
            rkn = kernel["remote_kernel_name"]
            remote_kernel_spec = remote_specs.get(rkn, {}).get("spec", {})
            remote_argv = remote_kernel_spec.get("argv", [])
            if remote_argv:
                results["remote_cmd"] = " ".join(remote_argv)
            r_interrupt_mode = remote_kernel_spec.get("interrupt_mode", "signal")
            results["interrupt_mode_remote"] = r_interrupt_mode
        else:
            results["kernel_ok"] = False
            k_name = kernel["remote_kernel_name"]
            log_msg_parts = [f"Remote kernel '{k_name}' not found on '{host_alias}'."]
            if results["exec_ok"] is False:
                log_msg_parts.append(
                    f"Remote Python '{remote_python}' may not be executable or found."
                )
            elif not remote_specs and results["exec_ok"] is True:
                # Python OK, but no specs.
                log_msg_parts.append(
                    f"Remote Python '{remote_python}' seems executable, "
                    "but no kernel specs were returned. "
                    "Ensure jupyter_client is installed and accessible by "
                    "this Python interpreter."
                )
            elif remote_specs:  # Specs found, but not the target kernel
                log_msg_parts.append(f"Available kernels: {list(remote_specs.keys())}.")
            logger.warning(" ".join(log_msg_parts))

    except Exception as e:
        logger.error(
            f"Error during remote checks for kernel '{kernel['name']}' on "
            f"'{kernel['host']}': {e}",
            exc_info=True,
        )
        # Some results might be populated if error happened after it was cached
        results["ssh_ok"] = False
        results["exec_ok"] = None
        results["kernel_ok"] = None
        results["rsd_ok"] = None

    return results


def format_ssh_kernel_info(k_lines, kernel, check_res):
    """Format SSH kernel information for display."""
    k_lines.append(f"{C}{K_NAME:<{K_LEN}}{N} {kernel['name']}")
    k_lines.append(f"{C}{K_DISP:<{K_LEN}}{N} {kernel['display_name']}")
    # For sshpyk kernels display the json file that should always exist
    fp_spec = Path(kernel["resource_dir"]) / "kernel.json"
    k_lines.append(f"{C}{K_SPEC:<{K_LEN}}{N} {fp_spec}")
    ssh_command = (
        f"ssh {kernel['host']} sshpyk-kernel "
        f"--SSHKernelApp.kernel_name={kernel['remote_kernel_name']} ..."
    )
    k_lines.append(f"{C}{K_CMDS:<{K_LEN}}{N} {ssh_command}")
    k_lines.append(f"{C}{K_LANG:<{K_LEN}}{N} {kernel['language']}")
    # interrupt_mode defaults to "signal" if not specified, but we always use
    # "message" in the kernel spec.
    c = format_check(check_res["interrupt_mode_ok"])
    k_lines.append(f"{C}{K_INT:<{K_LEN}}{N} {c} {kernel['interrupt_mode']}")

    c = format_check(check_res["ssh_exec_ok"])
    k_lines.append(f"{C}{K_SSH_PATH:<{K_LEN}}{N} {c} {check_res['ssh_path']}")

    host_prefix = ""
    for host, val in check_res["ssh_configs_val"].items():
        k_lines.append(f"{C}{K_SSH:<{K_LEN}}{N} {host}{host_prefix}")
        for k, (status, msg) in val.items():
            c = format_check(status)
            offset = "  "
            k_lines.append(f"{C}{'':<{K_LEN}}{N} {offset} {c} {k}: {msg}")
        host_prefix = " (jump)"

    c = format_check(check_res["ssh_ok"])
    k_lines.append(f"{C}{K_CONN:<{K_LEN}}{N} {c} {kernel['host']}")
    c = format_check(check_res["rsd_ok"])
    rsd = kernel["remote_script_dir"]
    if check_res["script_dir"]:
        rsd += f" ({check_res['script_dir']})"
    k_lines.append(f"{C}{K_RSD:<{K_LEN}}{N} {c} {rsd}")

    if check_res["uname"]:
        k_lines.append(f"{C}{K_RUNAME:<{K_LEN}}{N} {check_res['uname']}")
    if check_res["interrupt_mode_remote"]:
        k_lines.append(f"{C}{K_RINT:<{K_LEN}}{N} {check_res['interrupt_mode_remote']}")
    c = format_check(check_res["exec_ok"])
    k_lines.append(f"{C}{K_EXE:<{K_LEN}}{N} {c} {kernel['remote_python']}")
    c = format_check(check_res["kernel_ok"])
    k_lines.append(f"{C}{K_RKER:<{K_LEN}}{N} {c} {kernel['remote_kernel_name']}")
    k_lines.append(f"{C}{K_TIME:<{K_LEN}}{N} {kernel['launch_timeout']}")
    k_lines.append(f"{C}{K_TIME_SD:<{K_LEN}}{N} {kernel['shutdown_timeout']}")
    if check_res.get("remote_cmd"):
        k_lines.append(f"{C}{K_RCMD:<{K_LEN}}{N} {check_res['remote_cmd']}")


def format_check(check_status):
    """Format a check result with appropriate color based on boolean status."""
    if check_status in (False, "error"):
        check_symbol = "(x)"
        color = R
    elif check_status in (True, "ok"):
        check_symbol = "(v)"
        color = G
    elif check_status == "info":
        check_symbol = "(i)"
        color = N
    elif check_status == "warning":
        check_symbol = "(!)"
        color = W
    else:  # For None case
        check_symbol = "(?)"
        color = E

    return f"{color}{check_symbol}{N}"


def add_kernel(args: argparse.Namespace) -> None:
    """Add a new SSH kernel specification."""
    if (
        not args.display_name
        or not args.ssh_host_alias
        or not args.remote_python
        or not args.remote_kernel_name
    ):
        print(
            "Error: --display-name, --ssh-host-alias, "
            "--remote-python, and --remote-kernel-name are required."
        )
        sys.exit(1)

    # Validate SSH host alias
    if not RGX_SSH_HOST_ALIAS.match(args.ssh_host_alias):
        print(f"Error: Invalid SSH host alias '{args.ssh_host_alias}'")
        print(f"Must match pattern: {RGX_SSH_HOST_ALIAS.pattern!r}")
        sys.exit(1)

    # Validate remote kernel name
    if not RGX_KERNEL_NAME.match(args.remote_kernel_name):
        print(f"Error: Invalid remote kernel name '{args.remote_kernel_name}'")
        print(f"Must match pattern: {RGX_KERNEL_NAME.pattern!r}")
        sys.exit(1)

    # Generate kernel name if not provided
    kernel_name = (
        args.kernel_name or f"ssh_{args.ssh_host_alias}_{args.remote_kernel_name}"
    )

    # Check if kernel already exists
    ksm = KernelSpecManager()
    existing_specs = ksm.get_all_specs()

    if kernel_name in existing_specs and not args.replace:
        print(
            f"Error: Kernel '{kernel_name}' already exists. Use --replace to override "
            "or specify a different --kernel-name."
        )
        sys.exit(1)

    # Create kernel spec
    config = {
        "ssh": args.ssh or None,
        "ssh_host_alias": args.ssh_host_alias,
        "remote_python": args.remote_python,
        "remote_kernel_name": args.remote_kernel_name,
    }
    if args.launch_timeout:
        config["launch_timeout"] = args.launch_timeout
    if args.shutdown_timeout:
        config["shutdown_timeout"] = args.shutdown_timeout

    fp_sk = Path(sys.executable).parent / "sshpyk-kernel"
    if not fp_sk.is_file():
        logger.warning(f"Could not find sshpyk-kernel command at {fp_sk}")
        # For now don't exit. People can still fix it manually.
    kernel_spec = {
        # We populate the argv to allow external apps to launch the kernel "directly".
        # To ensure the provisioner is used we launch a SSHKernelApp instance locally.
        "argv": [
            # We make `python` the first argv because some external apps like, Jupyter
            # in VS Code, perform extra checks and they expect something like
            # `python -m ipykernel_launcher -f {connection_file}`. So we emulate that.
            str(sys.executable),  # should be absolute path
            str(fp_sk.absolute()),
            f"--SSHKernelApp.kernel_name={kernel_name}",
            # The SSHKernelProvisioner is aware of this and will use it if provided.
            "--KernelManager.connection_file='{connection_file}'",
        ],
        "display_name": args.display_name,
        "language": args.language,
        "interrupt_mode": "message",
        "metadata": {
            "kernel_provisioner": {
                "provisioner_name": "sshpyk-provisioner",
                "config": config,
            }
        },
    }

    kernel_dir = Path(ksm.user_kernel_dir) / kernel_name
    kernel_dir.mkdir(parents=True, exist_ok=True)
    with open(kernel_dir / "kernel.json", "w", encoding="utf-8") as f:
        json.dump(kernel_spec, f, indent=2)

    print(f"Kernel specification '{kernel_name}' installed in {kernel_dir}")


def edit_kernel(args: argparse.Namespace) -> None:
    """Edit an existing SSH kernel specification."""
    if not args.kernel_name:
        print("Error: --kernel-name is required for editing")
        sys.exit(1)

    ksm = KernelSpecManager()
    specs = ksm.get_all_specs()

    if args.kernel_name not in specs:
        print(f"Error: Kernel '{args.kernel_name}' not found")
        sys.exit(1)

    # Get the kernel spec path and data
    spec_info = specs[args.kernel_name]
    kernel_dir = spec_info["resource_dir"]
    kernel_json_path = Path(kernel_dir) / "kernel.json"
    kernel_spec = spec_info.get("spec", {})

    if not kernel_spec:
        print(f"Error: empty kernel spec at {kernel_json_path}")
        sys.exit(1)

    # Check if it's an SSH kernel
    metadata = kernel_spec.get("metadata", {})
    provisioner = metadata.get("kernel_provisioner", {})
    if provisioner.get("provisioner_name") != "sshpyk-provisioner":
        print(f"Error: Kernel '{args.kernel_name}' is not an SSH kernel")
        sys.exit(1)

    if args.display_name:
        kernel_spec["display_name"] = args.display_name

    if args.language:
        kernel_spec["language"] = args.language

    config = provisioner.get("config", {})

    if args.ssh:
        config["ssh"] = args.ssh
    if args.ssh_host_alias:
        if not RGX_SSH_HOST_ALIAS.match(args.ssh_host_alias):
            print(f"Error: Invalid SSH host alias '{args.ssh_host_alias}'")
            print(f"Must match pattern: {RGX_SSH_HOST_ALIAS.pattern}")
            sys.exit(1)
        config["ssh_host_alias"] = args.ssh_host_alias

    if args.remote_python:
        config["remote_python"] = args.remote_python

    if args.remote_kernel_name:
        if not RGX_KERNEL_NAME.match(args.remote_kernel_name):
            print(f"Error: Invalid remote kernel name '{args.remote_kernel_name}'")
            print(f"Must match pattern: {RGX_KERNEL_NAME.pattern}")
            sys.exit(1)
        config["remote_kernel_name"] = args.remote_kernel_name

    if args.launch_timeout:
        config["launch_timeout"] = args.launch_timeout
    if args.shutdown_timeout:
        config["shutdown_timeout"] = args.shutdown_timeout
    if args.remote_script_dir:
        config["remote_script_dir"] = args.remote_script_dir

    # Write updated kernel.json
    with open(kernel_json_path, "w", encoding="utf-8") as f:
        json.dump(kernel_spec, f, indent=2)

    print(f"Kernel specification '{args.kernel_name}' updated in {kernel_dir}")


def delete_kernel(args: argparse.Namespace) -> None:
    """Delete a kernel specification."""
    if not args.kernel_name:
        print("Error: kernel name is required for deletion")
        sys.exit(1)

    ksm = KernelSpecManager()

    try:
        path = ksm.remove_kernel_spec(args.kernel_name)
        print(f"Removed kernel specification '{args.kernel_name}' from {path}")
    except Exception as e:
        print(f"Error removing kernel specification: {e}")
        sys.exit(1)


def setup_logging(level: int) -> None:
    """Set up logging with the specified level."""
    logging.basicConfig(level=level, format=LOG_FORMAT)
    logger.debug("Logging initialized at level %s", logging.getLevelName(level))


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description=f"Manage SSH Jupyter kernels (version {__version__})"
    )

    # Add global logging argument
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase logs verbosity (-v for warning, -vv for info, -vvv for debug)",
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List command
    list_parser = subparsers.add_parser("list", help="List available kernels")
    list_parser.add_argument(
        "--remote", "-r", action="store_true", help="List only remote SSH kernels"
    )
    list_parser.add_argument(
        "--local", "-l", action="store_true", help="List only local kernels"
    )
    list_parser.add_argument(
        "--no-check", "-n", action="store_true", help="Skip remote kernel checks"
    )
    list_parser.set_defaults(func=list_kernels)

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new SSH kernel")
    add_parser.add_argument(
        "--kernel-name",
        help="Name for the kernel (default: ssh_<host>_<remote_kernel>)",
    )
    add_parser.add_argument("--display-name", help="Display name for the kernel")
    add_parser.add_argument("--language", required=True, help="Kernel language")
    add_parser.add_argument(
        "--ssh-host-alias",
        required=True,
        help="Remote host alias to connect to. It must be defined in your local SSH "
        "config file.",
    )
    add_parser.add_argument(
        "--remote-python",
        required=True,
        help="Path to the Python executable on the remote system. Run `which python` "
        "on the remote system to find its path. If the remote kernel is part of a "
        "virtual environment (e.g. conda env), first activate your virtual "
        "environment and then run `which python`. Note that `jupyter_client` "
        "package must be installed on the remote. You can confirm it with "
        "`python -m pip show jupyter_client'.",
    )
    add_parser.add_argument(
        "--remote-kernel-name",
        required=True,
        help="Kernel name on the remote system (i.e. first column of "
        "`jupyter-kernelspec list` on the remote system).",
    )
    add_parser.add_argument(
        "--launch-timeout",
        type=int,
        help=f"Timeout for launching the kernel (default: {LAUNCH_TIMEOUT})",
    )
    add_parser.add_argument(
        "--shutdown-timeout",
        type=int,
        help=f"Timeout for shutting down the kernel (default: {SHUTDOWN_TIME}). "
        "If the kernel does not shutdown within this time, "
        "it will be killed forcefully, "
        "after which an equal amount of time will be waited for the kernel to exit.",
    )
    add_parser.add_argument(
        "--remote-script-dir",
        help="Path to a remote directory for sshpyk scripts "
        + f"(default: {DEFAULT_REMOTE_SCRIPT_DIR})",
    )
    add_parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace existing kernel with the same name if it exists",
    )
    add_parser.add_argument(
        "--ssh",
        help="Path to SSH executable. If not specified, will be auto-detected using "
        "'which ssh'.",
    )
    add_parser.set_defaults(func=add_kernel)

    # Edit command
    edit_parser = subparsers.add_parser("edit", help="Edit an existing SSH kernel")
    edit_parser.add_argument(
        "--kernel-name", required=True, help="Name of the kernel to edit"
    )
    edit_parser.add_argument("--display-name", help="Display name for the kernel")
    edit_parser.add_argument("--language", help="Kernel language")
    edit_parser.add_argument(
        "--ssh-host-alias",
        help="Remote host alias to connect to. It must be defined in your local SSH "
        "config file.",
    )
    edit_parser.add_argument(
        "--remote-python",
        help="Path to the Python executable on the remote system. Run `which python` "
        "on the remote system to find its path. If the remote kernel is part of a "
        "virtual environment (e.g. conda env), first activate your virtual "
        "environment and then run `which python`. Note that `jupyter_client` "
        "package must be installed on the remote. You can confirm it with "
        "`python -m pip show jupyter_client'.",
    )
    edit_parser.add_argument(
        "--remote-kernel-name",
        help="Kernel name on the remote system (i.e. first column of "
        "`jupyter-kernelspec list` on the remote system).",
    )
    edit_parser.add_argument(
        "--launch-timeout",
        type=int,
        help="Timeout for launching the kernel",
    )
    edit_parser.add_argument(
        "--shutdown-timeout",
        type=int,
        help=f"Timeout for shutting down the kernel (default: {SHUTDOWN_TIME}). "
        "If the kernel does not shutdown within this time, "
        "it will be killed forcefully, "
        "after which an equal amount of time will be waited for the kernel to exit.",
    )
    edit_parser.add_argument(
        "--remote-script-dir",
        help="Path to a remote directory for sshpyk scripts. "
        "If not specified, the existing value will be kept.",
    )
    edit_parser.add_argument(
        "--ssh",
        help="Path to SSH executable. If not specified, will be auto-detected using "
        "'which ssh'.",
    )
    edit_parser.set_defaults(func=edit_kernel)

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a kernel")
    delete_parser.add_argument("kernel_name", help="Name of the kernel to delete")
    delete_parser.set_defaults(func=delete_kernel)

    # Parse arguments
    args = parser.parse_args()

    # Set up logging based on verbosity level
    log_level = logging.ERROR  # Default to ERROR level
    if args.verbose == 1:
        log_level = logging.WARNING
    elif args.verbose == 2:
        log_level = logging.INFO
    elif args.verbose >= 3:
        log_level = logging.DEBUG

    setup_logging(log_level)

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    # Execute the appropriate function
    args.func(args)


if __name__ == "__main__":
    main()
