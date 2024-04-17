from subprocess import run, PIPE
from shutil import which


def _remote_exe( argv ):
    result = [None,None]
    for p in zip(argv[1:][::2],argv[2:][::2]):
        if p[0] == '--python' or p[0] == "-p":
            result[0] = f'''{p[1]}/bin/python''' if len(p[1]) > 0 else None
        if p[0] == '--host' or p[0] == "-H":
            result[1] = p[1]
    return result

def kinfo_exe( kinfo ):
    '''Retrieve the python executables from a kernel info dictionary:

    Parameters
    ----------
    kinfo: dict
        Kernel info for one kernel specification

    Returns
    -------
    tuple: ( str, str, str )
        Returns a tuple containing (1) local Python path, (2) remote Python path, (3) remote
        host. If the spec is for a regular kernel, the last two elements will be None
    '''
    if kinfo['ssh']:
        return ( kinfo['spec']['argv'][0], *_remote_exe(kinfo['spec']['argv']) ) if kinfo['spec'] else ( None, None, None )
    else:
        return ( kinfo['spec']['argv'][0], None, None )


__rexists_checked = { }
def rexists( host, path ):
    '''Check to see if <path> exists on <host>:

    Parameters
    ----------
    host: str
        Hostname which accessible with SSH
    path: str
        The path to check for existence on on <host>

    Returns
    -------
    bool
        True if <path> exists on <host> otherwise False
    '''
    if f'''{host}:{path}''' in __rexists_checked:
        return __rexists_checked[f'''{host}:{path}''']

    if host is not None and path is not None:
        ssh = which('ssh')
        rproc = run( [ ssh, host, f'''file {path}/bin/python''' ], stdout=PIPE, stderr=PIPE )

        output = rproc.stdout.decode('ASCII')

        if len(output) == 0:
            __rexists_checked[f'''{host}:{path}'''] = False
            return False

        if '(No such file or directory)' in output:
            __rexists_checked[f'''{host}:{path}'''] = False
            return False

        __rexists_checked[f'''{host}:{path}'''] = True
        return True

    return False
