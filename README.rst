Remote Jupyter Kernels via SSH tunnels
######################################

The design of this package is based upon `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ which
in turn is based upon `remote_ikernel <https://bitbucket.org/tdaff/remote_ikernel>`_. This implementation shares
a common set of command line parameters with `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_, but it was
implemented from scratch to adapt to recent changes to :code:`jupyter_client` (which broke :code:`ssh_ipykernel`)
and to support Python 3.10. This package adds an :code:`ls` implementation which allows listing info about the
available kernel specifications.

While there are modest additions to `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_, there are
also modest subtractions. There are fewer configuration options for things like the internal name used
by `Jupyter Client <https://jupyter-client.readthedocs.io/en/stable/#>`_ to refer to the created
kernel.

Listing the Jupyter Kernels that are available
**********************************************

It can be difficult to know which Jupyter Kernels are available because there are multiple locations where
the `Kernel Spec files <https://jupyter-client.readthedocs.io/en/latest/kernels.html#kernel-specs>`_ can be
found. :code:`sshpyk` has an :code:`ls` option which lists the kernels that are available (even those which are
**not** `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ or :code:`sshpyk` kernels::

  bash$
  bash$ python -m sshpyk.kernel.ls --no-check -a
  python3                                   /Users/drs/develop/python/conda/envs/py310/share/jupyter/kernels/python3
  python3.8                                 /usr/local/share/jupyter/kernels/python3.8
  python3dbg                                /Users/drs/Library/Jupyter/kernels/python3dbg
  ssh__sshhost06test001                     /Users/drs/Library/Jupyter/kernels/ssh__sshhost06test001
  ssh__sshhost06test002                     /Users/drs/Library/Jupyter/kernels/ssh__sshhost06test002
  ssh_host06_host06homehost06condaenvspy310 /Users/drs/Library/Jupyter/kernels/ssh_host06_host06homehost06condaenvspy310
  bash$

The :code:`--no-check` flag indicates that the validity of the kernel spec files
should **not** be checked. The :code:`-a` (or :code:`--all`) flag indicates that it should show **all** kernel
specifications rather than just the ones for `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ or
:code:`sshpyk` kernel specification files.

If :code:`--no-check` is **not** supplied, part of listing the kernel information will include 
verify that the Python executable specified in the kernel specification exist on the local and remote systems.
This check allows the output to be colorized so red text indicates a problem. :code:`--local` will limit the
check to just the local Python executable and :code:`--remote` will limit the check to only the remote Python
executable. These options also list the local or remote Python path **instead** of the path to the kernel
specification directory.


Command line "ls" options
=========================

The following options are available for listing the Jupyter kernel specifications:

--help, -h
^^^^^^^^^^

              Show help information and exit.

--all, -a
^^^^^^^^^

              List all kernels that are available rather than just
              `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ and sshpyk kernels.

--local, -l
^^^^^^^^^^^

              Only list the information for the local Python executable.

--remote, -r
^^^^^^^^^^^^

              Only list the information for the remote Python executable.
              
--no-check
^^^^^^^^^^

              Do not check for the existence local or remote Python executables. This option
              can be used alone or with other options, e.g. with :code:`-l`. :code:`--no-check`
              avoids colorization to indicate problems so it can be useful for scripting.

--no-color
^^^^^^^^^^

              Do not colorize the listing to make it more convenient for processing output.

--verbose, -V
^^^^^^^^^^^^^

              Provide verbose output to make it easier to debug problems with kernel info.



Adding a new Kernel for a Remote System
***************************************

:code:`sshpyk` can also be used to add a specification file for a remote Python Kernel. For a
remote kernel to work

* :code:`ssypyk` must be installed on the local system
* :code:`ipykernel` must be installed on the remote system

Once these requirements are satisfied, the new kernel can be added like::

  bash$ python3 -m sshpyk.kernel.add --host host06 --python /home/host06/conda/envs/py310 --display-name 'host06 kernel'

This will add a Python kernel which will run on :code:`host06`, and it will be called
:code:`host06 kernel` when it is listed as an option for the user. We can check to see if it
is now included by using the :code:`ls` functionality::

  bash$ python3 -m sshpyk.kernel.ls -r -a --no-check
  python3                                   localhost:python
  python3.8                                 localhost:/opt/local/bin/python3.8
  python3dbg                                localhost:/Users/drs/develop/casagui-ic-debugging/iclean_demo_venv/bin/python
  ssh__sshhost06test001                     host06:/home/host06/conda/envs/py310/bin/python
  ssh__sshhost06test002                     host06:/home/host06/conda/envs/py310/bin/python
  ssh_host06_host06homehost06condaenvspy310 host06:/home/host06/conda/envs/py310/bin/python
  ssh_host06_host06kernel                   host06:/home/host06/conda/envs/py310/bin/python
  bash$

Unlike the example above, here we have asked that the remote Python path be displayed
instead of showing the kernel specification directory. Since we again asked that *all kernels*
be displayed instead of only the SSH kernels, a Python path is displayed for the
non-SSH kernels, but it is the local Python path as indicated by :code:`localhost:`.
Because these three kernels are non-SSH kernels this is the only Python path that is
available. However for the SSH kernels, we can see the remote Python path listed.
These paths are prefixed with the hostname, here :code:`host06:`. We can also see
the newly added kernel listed as :code:`ssh_host06_host06kernel`. This name is an internal
name created from the :code:`--display-name` string which the end user will typically
never see.

Command line "add" options
==========================

--help, -h
^^^^^^^^^^

             Show help information and exit.

--timeout TIMEOUT, -t TIMEOUT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

             Specify timeout to wait for kernel startup text.
             This option is **not used** by :code:`sshpyk`. It is only used by :code:`ssh_ipykernel`.

--env [ENV ...], -e [ENV ...]
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

             Specify environment variables for access by code executed within the remote Python
             kernel the form: :code:`"NAME=VALUE"`

--display-name DISPLAY_NAME, -d DISPLAY_NAME
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

             Specify the string to be used to describe this kernel to the end user.

--session
^^^^^^^^^

             Signal that session information should be stored in :code:`~/.sshpyk/sessions` for this kernel". This
             option is **not used** by :code:`ssh_ipykernel`. Note that when :code:`--session` is used the terminal
             output generated from the SSH connection is also directed to :code:`~/.sshpyk/sessions`.

--sudo, -s
^^^^^^^^^^

             Use :code:`sudo` to start kernel on the remote machine.
             This option is **not currently used** by :code:`sshpyk`. It is only used by :code:`ssh_ipykernel`.


--host HOST, -H HOST
^^^^^^^^^^^^^^^^^^^^

             The name of remote host as used to connect with SSH.

--python PATH, -p PATH
^^^^^^^^^^^^^^^^^^^^^^

             Path to remote python installation. This is the path to the root of the Python
             installation so the Python executable would be found in :code:`<PATH>/bin/python`.


SSH configuration notes
=======================

The host name used above is *different* from the Internet Protocol name for hosts which have
a well defined address. It is also a name apart from the physical network where the host can
be found. SSH allows for rationalizing the naming of the hosts to which you have access.
This is done through the :code:`$HOME/.ssh/config` file.

The most useful configuration option with respect to :code:`sshpyk` is the ability to set
up access to a host behind a `bastion host <https://en.wikipedia.org/wiki/Bastion_host>`_.
Assuming, the host named :code:`host06` from above is behind a bastion host, a configuration
entry in :code:`$HOME/.ssh/config` like::

  Host host06
    User HOST06-USERNAME
    ForwardX11Trusted yes
    ProxyCommand ssh BASTION-USERNAME@ssh.example.com -W %h:%p

will allow the *local* account to use its SSH credentials for the user name
:code:`BASTION-USERNAME` on :code:`ssh.example.com` for access to :code:`host06` which
is on some protected network behind :code:`ssh.example.com`. When the *local* account
runs :code:`ssh host06`, SSH will first connect as :code:`BASTION-USERNAME` on
:code:`ssh.example.com` and then it connect to host :code:`host06` as username
:code:`HOST06-USERNAME`.

This sort of configuration will allow :code:`host06` to be allowed as a hostname
for remote kernels.
