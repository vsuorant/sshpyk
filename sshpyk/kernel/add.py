from argparse import ArgumentParser, SUPPRESS

def _assignment(s):
    if type(s) != str or len(s) == 0:
        raise ValueError  # or TypeError, or `argparse.ArgumentTypeError
    eqindex = s.find("=")
    if eqindex < 0  or not s[0].isalpha( ) or not s[0:eqindex].isalnum( ):
        raise ValueError  # or TypeError, or `argparse.ArgumentTypeError
    return s

if __name__ == "__main__":
    from .. import add_kernel
    parse = ArgumentParser( add_help=False )
    optional = parse.add_argument_group("optional arguments")

    optional.add_argument( "--help", "-h", action="help", default=SUPPRESS, help="show this help message and exit" )
    optional.add_argument( "--timeout", "-t", type=int, default=5, help="specify timeout to use" )
    optional.add_argument( "--env", "-e", type=_assignment, nargs='*', default=[], help='add environment variable to set in the form: "NAME=VALUE"' )
    optional.add_argument( "--display-name", "-d", type=str, default=None, help='string which will be used to describe this kernel' )
    optional.add_argument( "--session", action="store_true", help="signal that session information should be stored for this kernel" )
    optional.add_argument( "--echo", action="store_true", help="echo SSH connection output to stdout" )
    optional.add_argument( "--sudo", "-s", action="store_true", help="sudo required to start kernel on remote machine" )

    required = parse.add_argument_group("required arguments")
    required.add_argument( "--host", "-H", required=True, help="name of remote host (as used to connect with ssh)" )
    required.add_argument( "--python", "-p", required=True, help='path to remote python installation ("PATH/bin/python" would be the python executable)' )

    args = parse.parse_args( )
    if args.display_name is None:
        args.display_name = f'''{args.host}: {args.python}'''

    add_kernel( args.host, args.display_name, args.python,
                env=args.env, sudo=args.sudo, system=args.sudo,
                timeout=args.timeout, session=args.session, echo=args.echo )
