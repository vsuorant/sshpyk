from argparse import ArgumentParser, SUPPRESS
from os.path import exists

from .utils import kinfo_exe as _exe
from .utils import rexists

def _red( s ):
    return f'''\033[31m{s}\033[0m'''

def _kernel_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        if info['ssh']:
            ### remote kernel spec
            if args.no_check or e[0] is not None and e[1] is not None and e[2] is not None and exists(e[0]) and rexists(e[2],e[1]):
                print(f'''{k.ljust(colsize)} {info['path']}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(info['path'])}''')
        else:
            ### local kernel spec
            if args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ):
                print(f'''{k.ljust(colsize)} {info['path']}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(info['path'])}''')

def _local_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        if args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ):
            print(f'''{k.ljust(colsize)} {e[0]}''')
        else:
            print(f'''{k.ljust(colsize)} {_red(e[0])}''')

def _remote_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        if info['ssh']:
            ### remote kernel spec
            if args.no_check or e[1] is not None and e[2] is not None and rexists(e[2],e[1]):
                print(f'''{k.ljust(colsize)} {e[2]}:{e[1]}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(e[2] + ':' + e[1])}''')
        else:
            print(f'''{k.ljust(colsize)} localhost:{e[0]}''')
    
if __name__ == "__main__":
    from .. import get_kernel_desc
    parse = ArgumentParser( add_help=False )

    optional = parse.add_argument_group("optional arguments")
    optional.add_argument( "--help", "-h", action="help", default=SUPPRESS, help="show this help message and exit" )
    optional.add_argument( "--all", "-a", action="store_true", help="list all kernels (not just ssh/sshpyk)" )
    optional.add_argument( "--local", "-l", action="store_true", help="list the information for the local python executable" )
    optional.add_argument( "--remote", "-r", action="store_true", help="list the information for the remote python executable" )
    optional.add_argument( "--no-check", "-nc", action="store_true", help="do not check for Python executables" )

    args = parse.parse_args( )

    kinfo = get_kernel_desc( all=args.all, valid_only=False )
    if args.local:
        _local_paths( kinfo )
    elif args.remote:
        _remote_paths( kinfo )
    else:
        _kernel_paths( kinfo )
