from argparse import ArgumentParser, SUPPRESS
from os.path import exists

from .utils import kinfo_exe as _exe
from .utils import rexists

def _red( s ):
    return s if args.no_color else f'''\033[31m{s}\033[0m'''

def _green( s ):
    return s if args.no_color else f'''\033[32m{s}\033[0m'''

def _kernel_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        if info['ssh']:
            ### remote kernel spec
            ###
            ###   e[0]  => local python path
            ###   e[1]  => remote python path
            ###   e[2]  => remote host name
            ###
            problems = [ ]
            ok = True
            if args.verbose:
                if e[0] is None:
                    problems.append( 'no local Python path provided' )
                    ok = False
                elif not exists(e[0]):
                    problems.append( f'''local Python path does not exist: {e[0]}''' )
                    ok = False
                if e[1] is None:
                    problems.append( 'no remote Python path provided' )
                    ok = False
                if e[2] is None:
                    problems.append( 'no remote host name provided' )
                    ok = False
                if e[1] is not None and e[2] is not None and not rexists(e[2],e[1]):
                    problems.append( f'''remote Python path does not exist: {e[1]}''' )
                    ok = False

            if args.verbose and ok or \
               not args.verbose and ( args.no_check or e[0] is not None and e[1] is not None and e[2] is not None and exists(e[0]) and rexists(e[2],e[1]) ):
                print(f'''{k.ljust(colsize)} {_green(info['path'])}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(info['path'])}''')
                for problem in problems:
                    print(f'''{k.ljust(colsize)} {_red('>>> ' + problem)}''')
        else:
            ### local kernel spec
            ###
            ###   e[0]   => local python path
            ###
            problems = [ ]
            ok = True
            if args.verbose:
                if e[0] is None:
                    problems.append( 'no local Python path provided' )
                    ok = False
                elif not exists(e[0]):
                    problems.append( f'''local Python path does not exist: {e[0]}''' )
                    ok = False

            if args.verbose and ok or \
               not args.verbose and ( args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ) ):
                print(f'''{k.ljust(colsize)} {_green(info['path'])}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(info['path'])}''')
                for problem in problems:
                    print(f'''{k.ljust(colsize)} {_red('>>> ' + problem)}''')

def _local_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        ###
        ###   e[0]   => local python path
        ###
        problems = [ ]
        ok = True
        if args.verbose:
            if e[0] is None:
                problems.append( 'no local Python path provided' )
                ok = False
            elif not exists(e[0]):
                problems.append( f'''local Python path does not exist: {e[0]}''' )
                ok = False

        if args.verbose and ok or \
           not args.verbose and ( args.no_check or e[0] is not None and ( not e[0].startswith('/') or exists(e[0]) ) ):
            print(f'''{k.ljust(colsize)} {_green(e[0])}''')
        else:
            print(f'''{k.ljust(colsize)} {_red(e[0])}''')
            for problem in problems:
                print(f'''{k.ljust(colsize)} {_red('>>> ' + problem)}''')

def _remote_paths( kinfo ):
    colsize = 0
    for k in kinfo.keys( ):
        if len(k) > colsize: colsize = len(k)
    for k,info in kinfo.items( ):
        e = _exe(info)
        if info['ssh']:
            ### remote kernel spec
            ###
            ###   e[0]  => local python path
            ###   e[1]  => remote python path
            ###   e[2]  => remote host name
            ###
            problems = [ ]
            ok = True
            if args.verbose:
                if e[1] is None:
                    problems.append( 'no remote Python path provided' )
                    ok = False
                if e[2] is None:
                    problems.append( 'no remote host name provided' )
                    ok = False
                if e[1] is not None and e[2] is not None and not rexists(e[2],e[1]):
                    problems.append( f'''remote Python path does not exist: {e[1]}''' )
                    ok = False

            if args.verbose and ok or \
               not args.verbose and ( args.no_check or e[1] is not None and e[2] is not None and rexists(e[2],e[1]) ):
                print(f'''{k.ljust(colsize)} {_green(e[2])}:{e[1]}''')
            else:
                print(f'''{k.ljust(colsize)} {_red(e[2] + ':' + e[1])}''')
                for problem in problems:
                    print(f'''{k.ljust(colsize)} {_red('>>> ' + problem)}''')

if __name__ == "__main__":
    from .. import get_kernel_desc
    parse = ArgumentParser( add_help=False )

    optional = parse.add_argument_group("optional arguments")
    optional.add_argument( "--help", "-h", action="help", default=SUPPRESS, help="show this help message and exit" )
    optional.add_argument( "--all", "-a", action="store_true", help="list all kernels (not just ssh/sshpyk)" )
    optional.add_argument( "--local", "-l", action="store_true", help="list the information for the local python executable" )
    optional.add_argument( "--remote", "-r", action="store_true", help="list the information for the remote python executable" )
    optional.add_argument( "--no-check", action="store_true", help="do not check for Python executables" )
    optional.add_argument( "--no-color", action="store_true", help="do not check for Python executables" )
    optional.add_argument( "--verbose", "-V", action="store_true", help="verbose output" )

    args = parse.parse_args( )

    kinfo = get_kernel_desc( all=args.all, valid_only=False )
    if args.local:
        _local_paths( kinfo )
    elif args.remote:
        _remote_paths( kinfo )
    else:
        _kernel_paths( kinfo )
