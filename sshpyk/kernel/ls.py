from argparse import ArgumentParser, SUPPRESS
from os.path import join, exists, basename
from subprocess import run, PIPE
from shutil import which
import json

def _red( s ):
    return f'''\033[31m{s}\033[0m'''

def _json( kernel_path ):
    with open( join( kernel_path, 'kernel.json' ) ) as f:
        return json.load(f)
    return None

def _remote_exe( argv ):
    result = [None,None]
    for p in zip(argv[1:][::2],argv[2:][::2]):
        if p[0] == '--python' or p[0] == "-p":
            result[0] = f'''{p[1]}/bin/python''' if len(p[1]) > 0 else None
        if p[0] == '--host' or p[0] == "-H":
            result[1] = p[1]
    return result

def _exe( kernel_path ):
    spec = _json(kernel_path)
    d = basename(kernel_path)
    if d.startswith('ssh_'):
        return ( spec['argv'][0], *_remote_exe(spec['argv']) ) if spec else ( None, None, None )
    else:
        return ( spec['argv'][0], None, None )

_rexists_checked_ = { }
def rexists( host, path ):
    if f'''{host}:{path}''' in _rexists_checked_:
        return _rexists_checked_[f'''{host}:{path}''']

    if host is not None and path is not None:
        ssh = which('ssh')
        rproc = run( [ ssh, host, f'''file {path}/bin/python''' ], stdout=PIPE, stderr=PIPE )

        output = rproc.stdout.decode('ASCII')

        if len(output) == 0:
            _rexists_checked_[f'''{host}:{path}'''] = False
            return False

        if '(No such file or directory)' in output:
            _rexists_checked_[f'''{host}:{path}'''] = False
            return False

        _rexists_checked_[f'''{host}:{path}'''] = True
        return True

    return False
        
def _kernel_paths( keys, kinfo ):
    ###
    ### Python is pathetic... you only get to traverse a filtered list once
    ###
    _keys = sorted(keys)
    colsize = 0
    for k in _keys:
        if len(k) > colsize: colsize = len(k)
    for k in _keys:
        e = _exe(kinfo[k])
        if k.startswith('ssh_'):
            ### remote kernel spec
            if args.no_check or e[0] is not None and e[1] is not None and e[2] is not None and exists(e[0]) and rexists(e[2],e[1]):
                print(f'''{k.ljust(colsize)} {kinfo[k]}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(kinfo[k])}''')
        else:
            ### local kernel spec
            if args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ):
                print(f'''{k.ljust(colsize)} {kinfo[k]}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(kinfo[k])}''')

def _local_paths( keys, kinfo ):
    ###
    ### Python is pathetic... you only get to traverse a filtered list once
    ###
    _keys = sorted(keys)
    colsize = 0
    for k in _keys:
        if len(k) > colsize: colsize = len(k)
    for k in _keys:
        e = _exe(kinfo[k])
        if args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ):
            print(f'''{k.ljust(colsize)} {e[0]}''')
        else:
            print(f'''{k.ljust(colsize)} {_red(e[0])}''')

def _remote_paths( keys, kinfo ):
    ###
    ### Python is pathetic... you only get to traverse a filtered list once
    ###
    _keys = sorted(keys)
    colsize = 0
    for k in _keys:
        if len(k) > colsize: colsize = len(k)
    for k in _keys:
        e = _exe(kinfo[k])
        if k.startswith('ssh_'):
            ### remote kernel spec
            if args.no_check or e[1] is not None and e[2] is not None and rexists(e[2],e[1]):
                print(f'''{k.ljust(colsize)} {e[2]}:{e[1]}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(e[2] + ':' + e[1])}''')
        else:
            print(f'''{k.ljust(colsize)} localhost:{e[0]}''')
    
if __name__ == "__main__":
    from .. import ls_kernel
    parse = ArgumentParser( add_help=False )

    optional = parse.add_argument_group("optional arguments")
    optional.add_argument( "--help", "-h", action="help", default=SUPPRESS, help="show this help message and exit" )
    optional.add_argument( "--all", "-a", action="store_true", help="list all kernels (not just ssh/sshpyk)" )
    optional.add_argument( "--local", "-l", action="store_true", help="list the information for the local python executable" )
    optional.add_argument( "--remote", "-r", action="store_true", help="list the information for the remote python executable" )
    optional.add_argument( "--no-check", "-nc", action="store_true", help="do not check for Python executables" )

    args = parse.parse_args( )

    kinfo = ls_kernel( )
    if args.local:
        _local_paths( kinfo.keys( ) if args.all else filter( lambda k: k.startswith('ssh_'), kinfo.keys( ) ), kinfo )
    elif args.remote:
        _remote_paths( kinfo.keys( ) if args.all else filter( lambda k: k.startswith('ssh_'), kinfo.keys( ) ), kinfo )
    else:
        _kernel_paths( kinfo.keys( ) if args.all else filter( lambda k: k.startswith('ssh_'), kinfo.keys( ) ), kinfo )
