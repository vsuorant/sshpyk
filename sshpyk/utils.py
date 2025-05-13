import json
import logging
import re
from pathlib import Path
from shutil import which
from subprocess import PIPE, STDOUT, run
from typing import Dict, List, Optional, Tuple, Union

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
UNAME_PREFIX = "UNAME_INFO_RESULT"
RGX_UNAME_PREFIX = re.compile(rf"{UNAME_PREFIX}=(.+)")
GET_SPECS_PREFIX = "GET_SPECS_RESULT"
RGX_GET_SPECS_PREFIX = re.compile(rf"{GET_SPECS_PREFIX}=(.+)")

SSHPYK_PERSISTENT_FP_BASE = "sshpyk-kernel"


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
                out["hostname"] = ("info", host)
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
            f"ProxyCommand: {proxy_cmd}, use ProxyJump instead.",
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
    cmd = [ssh, "-q", host_alias, f"echo -n '{UNAME_PREFIX}=' && uname -a"]
    log.debug(f"{lp}Verifying SSH connection to {host_alias!r}: {cmd = }")
    ret = run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )  # type: ignore
    raw_output = ret.stdout.strip()

    uname = ""
    for line in raw_output.splitlines():
        if not line:
            continue
        match = RGX_UNAME_PREFIX.search(line)
        if match:
            uname = match.group(1)
            break

    ok = ret.returncode == 0 and bool(uname)
    if not ok:
        msg = f"{lp}SSH connection to {host_alias!r} failed: {raw_output = !r}"
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
        f"echo -n '{GET_SPECS_PREFIX}=' && {python} -c '{GET_ALL_SPECS_PY}'",
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
    raw_output = ret.stdout.strip()
    lines = raw_output.splitlines()
    try:
        for line in lines:
            if not line:
                continue
            match = RGX_GET_SPECS_PREFIX.search(line)
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
