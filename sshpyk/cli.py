"""Command line interface to manage sshpyk kernel specifications."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict

from jupyter_client.kernelspec import KernelSpecManager

from .provisioning import RGX_KERNEL_NAME, RGX_SSH_HOST_ALIAS
from .utils import (
    fetch_remote_kernel_specs,
    verify_rem_executable,
    verify_ssh_connection,
)

logger = logging.getLogger(__name__)

# logging.basicConfig(level=logging.DEBUG)


# ANSI color codes for terminal output
G = "\033[32m"  # Green
R = "\033[31m"  # Red
N = "\033[39m"  # Reset color only, not formatting


def list_kernels(args: argparse.Namespace) -> None:
    """List all available kernels with sanity checks for SSH kernels."""
    # reset color upfront to avoid default color change after our color resets
    print(f"{N}", end="")
    specs = KernelSpecManager().get_all_specs()
    output_lines = []

    if not specs:
        print("No kernels available")
        return

    # Collect data first to determine column widths
    rows = []
    ssh_rows = []
    max_host_len = len("SSH Conn")  # Minimum width for header, renamed from "SSH Host"
    max_path_len = len("Path")  # Minimum width for header
    max_argv_len = len("Command")  # Minimum width for header

    # Cache for remote kernel specs to avoid multiple calls to the same host
    remote_specs_cache: Dict[str, Dict] = {}

    for name, spec_info in sorted(specs.items()):
        spec = spec_info.get("spec", {})
        display_name = spec.get("display_name", "")
        resource_dir = spec_info.get("resource_dir", "")
        argv = " ".join(spec.get("argv", []))

        # Check if it's an SSH kernel
        metadata = spec.get("metadata", {})
        provisioner = metadata.get("kernel_provisioner", {})
        is_ssh = provisioner.get("provisioner_name") == "sshpyk-provisioner"

        host = ""
        if is_ssh:
            config = provisioner.get("config", {})
            host = config.get("ssh_host_alias", "")
            remote_python_prefix = config.get("remote_python_prefix", "")
            remote_kernel_name = config.get("remote_kernel_name", "")

            # Generate command for SSH kernels
            ssh_command = (
                f"ssh {host} {remote_python_prefix}/bin/jupyter-kernel "
                + f"--KernelApp.kernel_name={remote_kernel_name}"
            )

            # Add 2 characters for the check mark and space
            max_host_len = max(max_host_len, len(host) + 2)
            max_argv_len = max(max_argv_len, len(ssh_command))

            # Add SSH kernel to regular rows with the command
            rows.append((name, display_name, host, resource_dir, ssh_command))

            ssh_rows.append(
                (
                    name,
                    display_name,
                    host,
                    remote_python_prefix,
                    remote_kernel_name,
                    resource_dir,
                    ssh_command,  # Use ssh_command instead of local argv that is empty
                    config.get("remote_kernel_launch_timeout", 60),  # Add timeout
                )
            )
        else:
            max_path_len = max(max_path_len, len(resource_dir))
            max_argv_len = max(max_argv_len, len(argv))
            rows.append((name, display_name, host, resource_dir, argv))

    # Format output for all kernels
    if rows:
        name_len = max(len(name) for name, _, _, _, _ in rows)
        name_len = max(name_len, len("Name"))

        display_len = max(len(display) for _, display, _, _, _ in rows)
        display_len = max(display_len, len("Display Name"))

        output_lines.append("Local Kernels:")
        output_lines.append(
            f"{'Display Name'.ljust(display_len)} | {'Name'.ljust(name_len)} | "
            f"{'Path'.ljust(max_path_len)} | {'Command'}"
        )
        output_lines.append(
            f"{'-' * display_len}-+-{'-' * name_len}-+-{'-' * max_path_len}-+-{'-' * max_argv_len}"  # noqa: E501
        )

        for name, display_name, _host, resource_dir, argv in rows:
            output_lines.append(
                f"{display_name.ljust(display_len)} | {name.ljust(name_len)} | "
                f"{resource_dir.ljust(max_path_len)} | {argv}"
            )
        if output_lines:
            print("\n".join(output_lines))

    output_lines = []

    # Process SSH kernels with sanity checks
    if ssh_rows:
        output_lines.append("\nRemote SSH Kernels:")

        max_argv_len = len("Command")  # Reset to minimum width for header

        # Calculate column widths for SSH table
        name_len = max(len(name) for name, _, _, _, _, _, _, _ in ssh_rows)
        name_len = max(name_len, len("Name"))

        display_len = max(len(display) for _, display, _, _, _, _, _, _ in ssh_rows)
        display_len = max(display_len, len("Display Name"))

        prefix_len = max(len(prefix) for _, _, _, prefix, _, _, _, _ in ssh_rows)
        # Add 2 characters for the check mark and space
        prefix_len = max(prefix_len + 2, len("Remote .../bin/jupyter-kernel"))

        kernel_len = max(len(kernel) for _, _, _, _, kernel, _, _, _ in ssh_rows)
        # Add 2 characters for the check mark and space
        kernel_len = max(kernel_len + 2, len("Kernel Spec"))

        # Add timeout column width
        timeout_len = len("Timeout")  # Minimum width for header

        # Print SSH table headers (without Path column)
        output_lines.append(
            f"{'Display Name'.ljust(display_len)} | {'Name'.ljust(name_len)} | "
            f"{'SSH Conn'.ljust(max_host_len)} | "
            f"{'Remote .../bin/jupyter-kernel'.ljust(prefix_len)} | "
            f"{'Kernel Spec'.ljust(kernel_len)} | "
            f"{'Timeout'.ljust(timeout_len)} | "
            f"{'Command'}"
        )
        # Add a placeholder for the separator line - will be updated after processing
        # all rows
        output_lines.append("")  # Empty placeholder for separator

        # Process each SSH kernel with checks
        for (
            name,
            display_name,
            host,
            remote_python_prefix,
            remote_kernel_name,
            _resource_dir,
            _argv,
            timeout,
        ) in ssh_rows:
            # Initialize check results (without colors)
            ssh_check = "✗"
            exec_check = "✗"
            k_check = "✗"
            remote_cmd = ""
            try:
                # Check SSH connection
                ssh_bin, ssh_ok, _ = verify_ssh_connection(host)
                if ssh_ok:
                    ssh_check = "✓"

                    # Check remote executable
                    exec_ok, _ = verify_rem_executable(
                        ssh_bin,
                        host,
                        str(Path(remote_python_prefix) / "bin" / "jupyter-kernel"),
                    )
                    if exec_ok:
                        exec_check = "✓"

                    # Check remote kernel exists
                    if host not in remote_specs_cache:
                        try:
                            remote_specs_cache[host] = fetch_remote_kernel_specs(
                                ssh_bin,
                                host,
                                str(Path(remote_python_prefix) / "bin" / "python"),
                            )
                        except Exception:
                            remote_specs_cache[host] = {}
                    remote_specs = remote_specs_cache.get(host, {})
                    kernel_ok = remote_kernel_name in remote_specs
                    if kernel_ok:
                        k_check = "✓"
                        # Get the remote kernel's argv
                        remote_kernel_spec = remote_specs.get(
                            remote_kernel_name, {}
                        ).get("spec", {})
                        remote_argv = remote_kernel_spec.get("argv", [])
                        if remote_argv:
                            remote_cmd = " ".join(remote_argv)
                            # Update max_argv_len with the actual remote command length
                            max_argv_len = max(max_argv_len, len(remote_cmd))
            except Exception as e:
                logger.error(f"Error checking kernel {name}: {e}")

            # Format SSH host with check mark/cross
            formatted_ssh_host = f"{R if ssh_check == '✗' else G}{ssh_check}{N} {host}"
            # Format remote prefix with check mark/cross
            formatted_remote_prefix = (
                f"{R if exec_check == '✗' else G}{exec_check}{N} {remote_python_prefix}"
            )
            # Format remote kernel with check mark/cross
            formatted_remote_kernel = (
                f"{R if k_check == '✗' else G}{k_check}{N} {remote_kernel_name}"
            )

            # Calculate the visible length (without ANSI color codes)
            visible_host_len = len(f"{ssh_check} {host}")
            visible_prefix_len = len(f"{exec_check} {remote_python_prefix}")
            visible_kernel_len = len(f"{k_check} {remote_kernel_name}")

            # Fix padding by adding spaces to account for ANSI color codes
            padding_host = max_host_len - visible_host_len
            padded_host = formatted_ssh_host + " " * padding_host

            padding_prefix = prefix_len - visible_prefix_len
            padded_prefix = formatted_remote_prefix + " " * padding_prefix

            padding_kernel = kernel_len - visible_kernel_len
            padded_kernel = formatted_remote_kernel + " " * padding_kernel

            # Format the row with all checks and information
            output_lines.append(
                f"{display_name.ljust(display_len)} | {name.ljust(name_len)} | "
                f"{padded_host} | {padded_prefix} | "
                f"{padded_kernel} | {str(timeout).ljust(timeout_len)} | "
                f"{remote_cmd}"
            )

        # After all rows are processed, create the separator line with the final
        # max_argv_len
        separator_line = (
            f"{'-' * display_len}-+-{'-' * name_len}-+-{'-' * max_host_len}-+-"
            f"{'-' * prefix_len}-+-{'-' * kernel_len}-+-{'-' * timeout_len}-+-"
            f"{'-' * max_argv_len}"
        )

        # Set the separator line in the output_lines
        output_lines[2] = separator_line

        if output_lines:
            print("\n".join(output_lines))


def add_kernel(args: argparse.Namespace) -> None:
    """Add a new SSH kernel specification."""
    if (
        not args.display_name
        or not args.ssh_host_alias
        or not args.remote_python_prefix
        or not args.remote_kernel_name
    ):
        print(
            "Error: --display-name, --language, --ssh-host-alias, "
            + "--remote-python-prefix, and --remote-kernel-name are required"
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
            + "or specify a different --kernel-name."
        )
        sys.exit(1)

    # Create kernel spec
    kernel_spec = {
        "argv": [],
        "display_name": args.display_name,
        "language": args.language or "",
        "interrupt_mode": "message",
        "metadata": {
            "kernel_provisioner": {
                "provisioner_name": "sshpyk-provisioner",
                "config": {
                    "ssh_host_alias": args.ssh_host_alias,
                    "remote_python_prefix": args.remote_python_prefix,
                    "remote_kernel_name": args.remote_kernel_name,
                    "remote_kernel_launch_timeout": args.remote_kernel_launch_timeout,
                },
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

    # Update kernel spec
    if args.display_name:
        kernel_spec["display_name"] = args.display_name

    if args.language:
        kernel_spec["language"] = args.language

    config = provisioner.get("config", {})

    if args.ssh_host_alias:
        if not RGX_SSH_HOST_ALIAS.match(args.ssh_host_alias):
            print(f"Error: Invalid SSH host alias '{args.ssh_host_alias}'")
            print(f"Must match pattern: {RGX_SSH_HOST_ALIAS.pattern}")
            sys.exit(1)
        config["ssh_host_alias"] = args.ssh_host_alias

    if args.remote_python_prefix:
        config["remote_python_prefix"] = args.remote_python_prefix

    if args.remote_kernel_name:
        if not RGX_KERNEL_NAME.match(args.remote_kernel_name):
            print(f"Error: Invalid remote kernel name '{args.remote_kernel_name}'")
            print(f"Must match pattern: {RGX_KERNEL_NAME.pattern}")
            sys.exit(1)
        config["remote_kernel_name"] = args.remote_kernel_name

    if args.remote_kernel_launch_timeout:
        config["remote_kernel_launch_timeout"] = args.remote_kernel_launch_timeout

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


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Manage SSH Jupyter kernels via SSH tunnels"
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List command
    list_parser = subparsers.add_parser("list", help="List available kernels")
    list_parser.set_defaults(func=list_kernels)

    # Add command
    add_parser = subparsers.add_parser("add", help="Add a new SSH kernel")
    add_parser.add_argument(
        "--kernel-name",
        help="Name for the kernel (default: ssh_<host>_<remote_kernel>)",
    )
    add_parser.add_argument("--display-name", help="Display name for the kernel")
    add_parser.add_argument(
        "--language", default="python", help="Kernel language (default: python)"
    )
    add_parser.add_argument("--ssh-host-alias", required=True, help="SSH host alias")
    add_parser.add_argument(
        "--remote-python-prefix",
        required=True,
        help="Path to Python prefix on remote system",
    )
    add_parser.add_argument(
        "--remote-kernel-name",
        required=True,
        help="Kernel name on the remote system. "
        + "Use `jupyter kernelspec list` on the remote system to find it.",
    )
    add_parser.add_argument(
        "--remote-kernel-launch-timeout",
        type=int,
        default=60,
        help="Timeout for launching the remote kernel (default: 60)",
    )
    add_parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace existing kernel with the same name if it exists",
    )
    add_parser.set_defaults(func=add_kernel)

    # Edit command
    edit_parser = subparsers.add_parser("edit", help="Edit an existing SSH kernel")
    edit_parser.add_argument(
        "--kernel-name", required=True, help="Name of the kernel to edit"
    )
    edit_parser.add_argument("--display-name", help="Display name for the kernel")
    edit_parser.add_argument("--language", help="Kernel language")
    edit_parser.add_argument("--ssh-host-alias", help="SSH host alias")
    edit_parser.add_argument(
        "--remote-python-prefix", help="Path to Python prefix on remote system"
    )
    edit_parser.add_argument(
        "--remote-kernel-name",
        help="Kernel name on the remote system. "
        + "Use `jupyter kernelspec list` on the remote system to find it.",
    )
    edit_parser.add_argument(
        "--remote-kernel-launch-timeout",
        type=int,
        help="Timeout for launching the remote kernel",
    )
    edit_parser.set_defaults(func=edit_kernel)

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a kernel")
    delete_parser.add_argument("kernel_name", help="Name of the kernel to delete")
    delete_parser.set_defaults(func=delete_kernel)

    # Parse arguments
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    # Execute the appropriate function
    args.func(args)


if __name__ == "__main__":
    main()
