import os
import re
import sys
import json
import time
from os import execvp
from pathlib import Path
from functools import reduce as fold
from uuid import uuid4
from shutil import which
from select import select
from os.path import isfile, join
from argparse import ArgumentParser, SUPPRESS
from subprocess import run, Popen, PIPE, STDOUT

from . import version

# No tabs, no multiline, quote { and } !
KERNEL_SCRIPT = """
import os
fname = os.path.expanduser("{fname}")
from jupyter_client import write_connection_file
write_connection_file(fname=fname, ip="{ip}", key=b"{key}", transport="{transport}", signature_scheme="{signature_scheme}", kernel_name="{kernel_name}")
fd = open(fname, "r")
ci = fd.read()
fd.close()
print(ci)
"""

def log( dest, msg ):
    if msg is not None and dest is not None:
        directory = os.path.dirname(dest)
        if directory: os.makedirs(directory,exist_ok=True)
        with open(dest,"a") as f:
            print(msg,file=f)

def store( conf ):
    path = join( Path.home( ), '.sshpyk', 'sessions', conf['host'] )
    try:
        ### umask modifies mode parameter of makedirs...
        ### however, umask=0 and mode=0o700 gives EVERYONE R/W/X permission...
        original_umask = os.umask(0o077)
        os.makedirs( path, exist_ok=True )
    finally:
        os.umask(original_umask)
    with open( join( path, f'''{conf['id']}.json''' ), "w" ) as f:
        json.dump( conf, f )

def main( host, python, connection_info, env, session, echo ):
    ssh = which('ssh')
    remote_id = uuid4( )
    remote_kernel_file = f'''/tmp/.sshpyk_{remote_id}.json'''
    substituted_script = KERNEL_SCRIPT.format(fname=remote_kernel_file, **connection_info)
    script = '; '.join(substituted_script.strip( ).split("\n"))

    ###
    ### Create remote kernel file with port information...
    ###
    result = run( [ ssh, host, f"""{python} -c '{script}'""" ], stdout=PIPE, stderr=PIPE )
    remote_state = json.loads(result.stdout.decode('utf-8'))

    if type(remote_state) != dict or len(remote_state) <= 0:
        exit( 'Creation of remote ipykernel state failed.' )

    ###
    ### Launch kernel on remote system with SSH tunnels between the local ports
    ### and the remote ports... tunnel format is '-L {local}:IP:{remote}' where
    ### IP is one of 127.0.0.1 or localhost (not sure if this is referring to
    ### the local or remote host...
    ###
    ### This also removes the kernel configuration file after the ipykernel exits...
    ###
    ssh_env = env if env else [ ]
    ssh_tunnels = fold( lambda acc,k: [ '-L', f'''{connection_info[k]}:{connection_info['ip']}:{remote_state[k]}''' ] + acc,
                        filter( lambda k: k.endswith('_port'), remote_state.keys() ), [] )

    ###
    ### start remote kernel...
    ###
    proc = Popen( [ 'ssh', '-q', '-t', *ssh_tunnels, host, f'''{' '.join(ssh_env)} bash -c "echo PID $$; exec {python} -m ipykernel_launcher --HistoryManager.hist_file=:memory: -f {remote_kernel_file}"; echo {remote_id} $? >> "/tmp/.sshpyk_status.$USER.txt"; rm -f {remote_kernel_file}''' ],
                  stdout=PIPE, stderr=STDOUT )

    ###
    ### collect startup info...
    ###
    log_output = join( Path.home( ), '.sshpyk', 'sessions', host, f'''{remote_id}.txt''' ) if session else None
    remote_pid = -1
    tries = 100
    while tries > 0:
        ###
        ### sites seem to like to generate a belch of boilerplate when logging in...
        ### sift through the cruft looking for "PID <pid>"...
        ###
        readable, writable, exceptional = select( [proc.stdout], [], [] )
        if proc.stdout in readable:
            line = proc.stdout.readline( )
            if line:
                decoded = line.decode('utf-8')
                if echo: print( decoded )
                log( log_output, decoded )
                try:
                    ### this should ignore any cruft up to "PID <pid>" and extract <pid>
                    remote_pid = int(re.compile(r".*?PID (\d+)").match(decoded).group(1))
                    break
                except: pass
            else: break

        tries -= 1
        try:
            readable, writable, exceptional = select( [proc.stdout], [], [] )
            if proc.stdout not in readable:
                time.sleep(0.5)
        except: pass               ### jupyter_client.KernelManager.shutdown_kernel( ) seems to be based upon
                                   ### sending a KeyboardInterrupt exception...
                                   ### When executing a script, the KeyboardInterrupt can be sent before the
                                   ### <pid> has been collected... but maybe pass isn't exactly the right
                                   ### thing to do anyway...

    ###
    ### store session information...
    ###
    if session:
        store( { 'host': host, 'id': str(remote_id), 'pid': remote_pid,
                 'paths': { 'ssh': ssh, 'remote py': python, 'local py': sys.executable, 'remote kernel file': remote_kernel_file },
                 'connect': { 'local': connection_info, 'remote': remote_state } } )

    ###
    ### Here we will need to eventually be able to separate (background) the remote kernel so that we
    ### can stop and reconnect to the remote kernel from another network (e.g.)... maybe
    ### https://stackoverflow.com/a/60309743/2903943
    ###
    try:
        for line in proc.stdout:
            info = line.decode( )
            if echo: print( info )
            log( log_output, info )
            sys.stdout.flush( )
    except: pass                   ### KeyboardInterrupt can occur here...
    try:
        proc.wait( )
    except: pass                   ### KeyboardInterrupt can occur here...


if __name__ == "__main__":
    parse = ArgumentParser( add_help=False )
    optional = parse.add_argument_group("optional arguments")

    ### prevents --help from appearing in it's own "options:" group
    optional.add_argument( "--help", "-h", action="help", default=SUPPRESS, help="show this help message and exit" )
    optional.add_argument( "--version", action='version', version=f'''sshrpy {version( )}''' )

    optional.add_argument( "--timeout", "-t", type=int, help="timeout for remote commands", default=5 )
    optional.add_argument( "--name", "-n", type=str, help="kernel name" )
    optional.add_argument( "--env", "-e", nargs="*",
                           help="environment variables for the remote kernel in the form: VAR1=value1 VAR2=value2" )
    optional.add_argument( "--session", action="store_true", help="store session information for this kernel" )
    optional.add_argument( "--echo", action="store_true", help="echo SSH connection output to stdout" )
    optional.add_argument( "-s", action="store_true", help="sudo required to start kernel on the remote machine" )


    required = parse.add_argument_group("required arguments")
    required.add_argument( "--file", "-f", required=True, help="jupyter kernel connection file" )
    required.add_argument( "--host", "-H", required=True, help="remote host" )
    required.add_argument( "--python", "-p", required=True, help="remote python_path" )

    args = parse.parse_args( )

    if args.name is not None:
        if len(args.name.split( )) > 1:
            exit( f'''Provided kernel name ('{args.name}') cannot contain whitespace.''' )

    if not isfile(args.file):
        exit( f'''Specified file ('{args.file}') does not exist.''' )

    with open(args.file, "r") as fd:
        connection_info = json.loads(fd.read())

    ## seems like newer versions of the connection file do not include 'kernel_name'
    if args.name is not None:
        connection_info['kernel_name'] = args.name
    elif 'kernel_name' not in connection_info:
        connection_info['kernel_name'] = f'''ipykrn{os.getpid( )}'''

    main( args.host, join(args.python, 'bin', 'python'), connection_info, args.env, args.session, args.echo )
