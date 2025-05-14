import json
import logging
import re
from pathlib import Path
from shutil import which
from subprocess import PIPE, STDOUT, Popen, run
from typing import Any, Dict, List, Optional, Tuple, Union

from jupyter_client.connect import find_connection_file

logger = logging.getLogger(__name__)


def inline_script(script: str):
    lines = (line.strip() for line in script.splitlines())
    return "; ".join(line for line in lines if line)


GET_ALL_SPECS_PY = inline_script(
    (Path(__file__).parent / "get_all_specs.py").read_text()
)


LAUNCH_TIMEOUT = 15
SHUTDOWN_TIME = 15
UNAME_PREFIX = "SSHPYK_UNAME_INFO"
RGX_UNAME_PREFIX = re.compile(rf"{UNAME_PREFIX}=(.+)")
KERNEL_SPECS_PREFIX = "SSHPYK_KERNEL_SPECS"
RGX_KERNEL_SPECS_PREFIX = re.compile(rf"{KERNEL_SPECS_PREFIX}=(.+)")
REMOTE_PYTHON_EXEC_PREFIX = "SSHPYK_REMOTE_PYTHON_EXEC"
RGX_REMOTE_PYTHON_EXEC_PREFIX = re.compile(rf"{REMOTE_PYTHON_EXEC_PREFIX}=(\d+)")
REMOTE_SCRIPT_DIR_PREFIX = "SSHPYK_REMOTE_SCRIPT_DIR"
RGX_REMOTE_SCRIPT_DIR_PREFIX = re.compile(rf"{REMOTE_SCRIPT_DIR_PREFIX}=(.+)")
REMOTE_SCRIPT_DIR_OK_PREFIX = "SSHPYK_REMOTE_SCRIPT_DIR_OK"
RGX_REMOTE_SCRIPT_DIR_OK_PREFIX = re.compile(rf"{REMOTE_SCRIPT_DIR_OK_PREFIX}=(\d+)")

SSHPYK_PERSISTENT_FP_BASE = "sshpyk-kernel"

DEFAULT_REMOTE_SCRIPT_DIR = "$HOME/.ssh/sshpyk"


def verify_local_ssh(
    ssh: Optional[str], log: logging.Logger = logger, name: str = "ssh", lp: str = ""
) -> str:
    """Verify that the local SSH is working."""
    if not ssh:
        ssh = which(name)
        if not ssh:
            log.warning(f"{lp}Local {name} executable not found.")
        else:
            log.info(f"{lp}Auto-detected {name} executable: {ssh}")
    if not ssh:
        raise EnvironmentError(f"{lp}Local {name} executable not found.")
    cmd = [ssh, "-V"]
    log.debug(f"{lp}Verifying local {name} {cmd = }")
    ret = run(  # noqa: S603
        cmd,
        stdout=PIPE,
        stderr=STDOUT,  # at least OpenSSH outputs version to stderr
        text=True,
        check=False,
    )  # type: ignore
    ok = ret.returncode == 0
    out = ret.stdout.strip()
    if not ok:
        msg = f"{lp}Local {name} verification failed: {out!r}"
        log.error(msg)
        raise EnvironmentError(msg)
    log.debug(f"{lp}Local {name} verification succeeded, {name} version: {out}")
    return ssh


def parse_ssh_config(config: str):
    lines = (line.strip() for line in config.strip().splitlines())
    tuples = (line.split(" ", 1) for line in lines if " " in line)
    # .lower() just in case, SSH already prints in lowercase
    configs = ((key.strip().lower(), value.strip()) for key, value in tuples)

    out: Dict[str, Union[str, List[str]]] = {}
    # ! there can be multiple entries for the same config key, e.g. IdentityFile
    for key, value in configs:
        if key in out:
            if isinstance(out[key], list):
                out[key].append(value)  # type: ignore
            else:
                out[key] = [out[key], value]  # type: ignore
        else:
            out[key] = value
    return out


def get_local_ssh_configs(
    ssh: str,
    alias: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> List[Dict[str, Union[str, List[str]]]]:
    aliases = [alias]
    hosts_configs = []
    while aliases:
        alias = aliases.pop(0)
        # ! for non-defined aliases, it will still dump a config based on defaults
        cmd = [ssh, "-G", alias]  # dumps all configs for the alias
        log.debug(f"{lp}Reading local SSH config for {alias!r}: {cmd = }")
        ret = run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )  # type: ignore
        ok = ret.returncode == 0
        if not ok:
            stderr = ret.stderr.strip()
            msg = f"{lp}Reading local SSH config for {alias!r} failed: {stderr!r}"
            log.error(msg)
            raise EnvironmentError(msg)
        config = parse_ssh_config(ret.stdout)
        log.debug(f"{lp}Local SSH config for host alias {alias!r}: {config}")
        proxy_jump = config.get("proxyjump", None)
        if proxy_jump:
            if isinstance(proxy_jump, list):
                log.warning(
                    f"{lp}SSH reports more than one ProxyJump for {alias!r}: "
                    "{proxy_jump!r}. This is likely a misconfiguration!"
                )
                # ? is this SSH config possible/valid at all?
                aliases.append(proxy_jump[0])
            else:
                aliases.append(proxy_jump)
        hosts_configs.append(config)
    log.debug(f"{lp}Read {len(hosts_configs)} local SSH configs")
    return hosts_configs


def validate_ssh_config(
    config: Dict[str, Union[str, List[str]]],
    log: logging.Logger = logger,
    lp: str = "",
):
    out = {}
    keys = [
        "hostname",
        "user",
        "identityfile",
        "controlmaster",
        "controlpersist",
        "controlpath",
        "proxyjump",
        "proxycommand",
    ]
    for key in tuple(keys):
        if isinstance(config.get(key, None), list):
            out[key] = (
                "error",
                f"Likely missing in your ssh config. Multiple values: {config[key]}.",
            )
            del keys[keys.index(key)]

    if "user" in keys:
        if "user" not in config:
            out["user"] = ("error", "Missing, must be set in the ssh config.")
        else:
            out["user"] = ("info", config["user"])

    if "hostname" in keys:
        host = config.get("host", None)
        if host:
            hostname = config.get("hostname", None)
            if host != hostname:
                out["hostname"] = ("info", hostname)
            else:
                out["hostname"] = (
                    "error",
                    "Likely missing in your ssh config. "
                    f"{host=!r} and {hostname=!r} must be different.",
                )
        else:
            out["hostname"] = ("error", "Missing, must be set in the ssh config.")

    if "identityfile" in keys:
        id_file = config.get("identityfile", None)
        if id_file:
            fp = Path(id_file).resolve()  # type: ignore
            if fp.exists():
                out["identityfile"] = ("ok", str(fp))
            else:
                out["identityfile"] = (
                    "error",
                    f"'{fp}' does not exist. Make sure the private key file exists!",
                )
        else:
            out["identityfile"] = (
                "warning",
                "Missing, it is recommended to use private key authentication.",
            )

    if "controlmaster" in keys:
        cm = config.get("controlmaster", None)
        if cm:
            if cm == "auto":
                out["controlmaster"] = ("ok", "auto")
            else:
                out["controlmaster"] = (
                    "error",
                    f"Must be 'auto', not {cm!r}.",
                )
        else:
            out["controlmaster"] = ("error", "Missing, must be 'auto'.")

    if "controlpersist" in keys:
        c_persist = config.get("controlpersist", None)
        if c_persist:
            if c_persist not in ("no", "false"):
                out["controlpersist"] = ("ok", c_persist)
            else:
                out["controlpersist"] = (
                    "error",
                    f"Must be, e.g., '10m' or 'yes', not {c_persist!r}.",
                )
        else:
            out["controlpersist"] = ("error", "Missing, recommended '10m' (or larger).")

    if "controlpath" in keys:
        c_path = config.get("controlpath", None)
        recommended = "~/.ssh/sshpyk_%r@%h_%p"
        if c_path:
            dp = Path(c_path).resolve().parent  # type: ignore
            if dp.exists():
                out["controlpath"] = ("ok", c_path)
            else:
                out["controlpath"] = (
                    "error",
                    f"Parent dir '{dp}' does not exist! Parent dir must exist!",
                )
        else:
            out["controlpath"] = ("error", f"Missing, use, e.g., {recommended!r}.")

    proxy_cmd = config.get("proxycommand", None)
    if "proxycommand" in keys and proxy_cmd:
        out["proxycommand"] = (
            "warning",
            f"ProxyCommand: {proxy_cmd!r}. "
            "Use ProxyJump instead if reaching this host requires a Bastion host!",
        )

    if "proxyjump" in keys:
        proxy_jump = config.get("proxyjump", None)
        if proxy_jump:
            out["proxyjump"] = ("info", proxy_jump)  # nothing we can check about this

    return out


def verify_ssh_connection(
    ssh: str,
    host_alias: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> Tuple[bool, str, str]:
    """Verify that the SSH connection to the remote host is working."""
    cmd = [ssh, "-q", host_alias, f'echo "{UNAME_PREFIX}=$(uname -a)"']
    log.debug(f"{lp}Verifying SSH connection to {host_alias!r}: {cmd = }")
    ret = run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )  # type: ignore
    stdout = ret.stdout.strip()

    uname = ""
    for line in stdout.splitlines():
        if not line:
            continue
        match = RGX_UNAME_PREFIX.search(line)
        if match:
            uname = match.group(1)
            break

    ok = ret.returncode == 0 and bool(uname)
    if not ok:
        msg = f"{lp}SSH connection to {host_alias!r} failed: {stdout = !r}"
        log.error(msg)
    else:
        msg = f"{lp}SSH connection to {host_alias!r} succeeded: {uname = !r}"
        log.debug(msg)
    return ok, msg, uname


def verify_rem_executable(
    ssh: str,
    host_alias: str,
    fp: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> Tuple[bool, str]:
    """Verify that the remote executable exists and is executable."""
    # NB the quotes around filename are mandatory and safer
    cmd = [ssh, host_alias, f'test -e "{fp}" && test -r "{fp}" && test -x "{fp}"']
    log.debug(f"{lp}Verifying remote executable {fp!r} on {host_alias!r}: {cmd = }")
    ret = run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )  # type: ignore
    ok = ret.returncode == 0
    ret_str = ret.stdout.strip()
    if not ok:
        msg = f"{lp}Remote {fp!r} not found/readable/executable ({ret_str!r})"
        log.error(msg)
    else:
        msg = f"{lp}Remote {fp!r} exists, is readable and executable."
        log.debug(msg)
    return ok, msg


def verify_rem_dir_exists(
    ssh: str,
    host_alias: str,
    dir_path: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> Tuple[bool, str]:
    """Verify that the remote directory exists."""
    # NB the quotes around dir_path are mandatory and safer
    cmd = [ssh, host_alias, f'test -d "{dir_path}"']
    log.debug(
        f"{lp}Verifying remote directory {dir_path!r} on {host_alias!r}: {cmd = }"
    )
    ret = run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )  # type: ignore
    ok = ret.returncode == 0
    if not ok:
        msg = f"{lp}Remote directory {dir_path!r} does not exist or is not a directory."
        # Don't log as error, it might be an expected non-existent default path
        log.debug(msg)
    else:
        msg = f"{lp}Remote directory {dir_path!r} exists."
        log.debug(msg)
    return ok, msg


def fetch_remote_kernel_specs(
    ssh: str,
    host_alias: str,
    python: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> dict:
    """
    Fetch kernel specifications from the remote host using SSH.
    Returns a dictionary of kernel specs from the remote system.
    """
    cmd = [
        ssh,
        host_alias,
        # ! `echo -n` is not supported on all systems, use `printf` instead.
        f"printf '{KERNEL_SPECS_PREFIX}=' && {python} -c '{GET_ALL_SPECS_PY}'",
    ]
    log.debug(f"{lp}Fetching remote kernel specs from {host_alias!r}: {cmd = }")
    ret = run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )  # type: ignore
    if ret.returncode != 0:
        msg = f"{lp}Failed to fetch remote kernel specs: {ret.stderr.strip()!r}"
        log.error(msg)
        raise RuntimeError(msg)
    stdout = ret.stdout.strip()
    lines = stdout.splitlines()
    try:
        for line in lines:
            if not line:
                continue
            match = RGX_KERNEL_SPECS_PREFIX.search(line)
            if match:
                specs = json.loads(match.group(1))
                break
    except json.JSONDecodeError as e:
        msg = f"{lp}Failed to parse remote kernel specs: {e}"
        log.error(msg)
        raise RuntimeError(msg) from e

    log.info(f"{lp}Successfully fetched {len(specs)} kernel specs from {host_alias!r}")
    return specs


def find_persistent_file(
    filename: str = f"{SSHPYK_PERSISTENT_FP_BASE}-*.json",
    path: Union[str, List[str], None] = None,
    profile: Optional[str] = None,
) -> str:
    """
    Find a persistent file by name or glob pattern.
    The persistent file is a JSON file that contains the provisioner info.

    This function is a wrapper around `jupyter_client.connect.find_connection_file`.
    See the docstring of that function for details.
    """
    return find_connection_file(filename, path, profile)


def remote_checks(
    ssh_bin: str,
    host_alias: str,
    remote_python_path: str,
    remote_script_dir: str,
    log: logging.Logger = logger,
    lp: str = "",
) -> Dict[str, Any]:
    """
    Performs multiple checks on the remote host via a single SSH call.
    Checks: uname, remote python executable, remote script directory, and kernel specs.
    """
    results: Dict[str, Any] = {
        "uname": None,
        "python_exec_ok": None,
        "script_dir_ok": None,
        "script_dir": None,
        "remote_specs": None,
        "err_msg": None,
        "stdout": None,
    }
    rpy_safe = f'"{remote_python_path}"'
    commands = [
        f'echo "{UNAME_PREFIX}=$(uname -a)"',
        f"FP_PY={rpy_safe}",
        'test -e "$FP_PY" && test -r "$FP_PY" && test -x "$FP_PY"',
        f'echo "{REMOTE_PYTHON_EXEC_PREFIX}=$?"',
        # Use the user-provided remote_script_dir directly, letting remote shell
        # handle expansion
        f'RS_DIR_FD="{remote_script_dir}"',
        'test -d "$RS_DIR_FD"',
        f'echo "{REMOTE_SCRIPT_DIR_PREFIX}=$RS_DIR_FD"',
        f'echo "{REMOTE_SCRIPT_DIR_OK_PREFIX}=$?"',
        # If remote_python_path is invalid, this command part will fail.
        f"printf '{KERNEL_SPECS_PREFIX}=' && {rpy_safe} -c '{GET_ALL_SPECS_PY}'",
    ]
    # Using -q for ssh to suppress banners and diagnostic messages.
    # Commands are joined by ';' to ensure all attempt to run.
    cmd_str = "; ".join(commands)
    cmd = [ssh_bin, "-vvv", host_alias, cmd_str]
    log.debug(f"{lp}Performing remote checks on {host_alias!r} with {cmd_str = }")
    try:
        process = Popen(  # noqa: S603
            cmd,
            stdout=PIPE,
            stderr=PIPE,
            stdin=PIPE,
            bufsize=1,
            universal_newlines=True,
        )  # type: ignore
    except Exception as e:
        msg = f"{lp}Failed to execute remote checks command on {host_alias!r}: '{e}'"
        log.error(msg)
        results["err_msg"] = msg
        return results

    stdout, stderr = process.communicate(timeout=LAUNCH_TIMEOUT)
    results["stdout"] = stdout.strip()
    results["stderr"] = stderr.strip()
    process.stdin.close()
    process.terminate()
    process.wait()

    # Even if ret.returncode != 0, there might be partial results in stdout.
    if process.returncode != 0:
        msg = (
            f"{lp}SSH command for checks on {host_alias!r} exited "
            f"with rc={process.returncode}. "
            f"stdout: '{stdout}'. "
            f"stderr: '{stderr}'."
        )
        log.warning(msg)
        # Store a general error message if one isn't more specifically set later.
        if not results["err_msg"]:
            results["err_msg"] = msg

    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        log.debug(f"{lp}(stderr) {line}")

    parsed_specs = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        uname_match = RGX_UNAME_PREFIX.search(line)
        if uname_match:
            results["uname"] = uname_match.group(1).strip()
            log.debug(f"{lp}Parsed uname: {results['uname']}")
            continue

        py_exec_match = RGX_REMOTE_PYTHON_EXEC_PREFIX.search(line)
        if py_exec_match:
            results["python_exec_ok"] = py_exec_match.group(1).strip() == "0"
            log.debug(f"{lp}Parsed python_exec_ok: {results['python_exec_ok']}")
            continue

        script_dir_match = RGX_REMOTE_SCRIPT_DIR_OK_PREFIX.search(line)
        if script_dir_match:
            results["script_dir_ok"] = script_dir_match.group(1).strip() == "0"
            log.debug(f"{lp}Parsed script_dir_ok: {results['script_dir_ok']}")
            continue

        script_dir_match = RGX_REMOTE_SCRIPT_DIR_PREFIX.search(line)
        if script_dir_match:
            results["script_dir"] = script_dir_match.group(1).strip()
            log.debug(f"{lp}Parsed script_dir: {results['script_dir']}")
            continue

        if not parsed_specs:
            specs_match = RGX_KERNEL_SPECS_PREFIX.search(line)
            if specs_match:
                try:
                    specs_json_str = specs_match.group(1).strip()
                    results["remote_specs"] = json.loads(specs_json_str)
                    num_specs = len(results["remote_specs"])
                    log.debug(f"{lp}Parsed {num_specs} remote kernel specs.")
                    parsed_specs = True
                except json.JSONDecodeError as e:
                    err_msg = (
                        f"Failed to parse remote kernel specs JSON: '{e}'. "
                        f"JSON string: '{specs_json_str}'"
                    )
                    log.error(f"{lp}{err_msg}")
                    err_msg = f"{results.get('err_msg', '')}; {err_msg}".lstrip("; ")
                    results["err_msg"] = err_msg
                    # Indicate parsing failure with empty dict
                    results["remote_specs"] = {}
                    parsed_specs = True  # Attempted parsing
                continue

        log.debug(f"{lp}Unparsed line: {line}")

    if results["remote_specs"] is None:  # If no prefix match at all
        log.debug(
            f"{lp}Remote kernel specs prefix '{KERNEL_SPECS_PREFIX}' not found in "
            f"output."
        )
        results["remote_specs"] = {}

    if results["uname"] is None and not results.get("err_msg", None):
        msg = f"Failed to retrieve uname from remote host {host_alias!r}."
        log.debug(f"{lp}{msg}")
        results["err_msg"] = f"{results.get('err_msg', '')}; {msg}".lstrip("; ")

    return results
