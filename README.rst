Remote Jupyter Kernels via SSH tunnels
======================================

The design of this pakage is based upon `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ which is
in turn based upon `remote_ikernel <https://bitbucket.org/tdaff/remote_ikernel>`_. This implementation shares
the same command line parameters as `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_, but it was
reimplemented from scratch to support Python 3.10. It also includes an :code:`ls` implementation which allows
checking on the available kernel specifications.

While there are modest additions to `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_, there are
also modest subtractions. There are fewer configuration options for things like the name that
`Jupyter Client <https://jupyter-client.readthedocs.io/en/stable/#>`_ uses to refer to the
kernel. This is still based on the kernel description that the user sees, but the entire name
is no longer completely configurable.

Listing the Jupyter Kernels that are available
==============================================

It can be difficult to know which Jupyter Kernels are available because there is more than one location that
the `Kernel Spec files <https://jupyter-client.readthedocs.io/en/latest/kernels.html#kernel-specs>`_ can be
stored. :code:`sshpyk` has an :code:`ls` option to all for seeing which kernels are available (even if they are
**not** `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ or :code:`sshpyk` kernels::

  bash$ 
  bash$ python -m sshpyk.kernel.ls --no-check -a
  python3                                          /Users/drs/develop/python/conda/envs/py310-sshipy/share/jupyter/kernels/python3
  python3.8                                        /usr/local/share/jupyter/kernels/python3.8
  python3dbg                                       /Users/drs/Library/Jupyter/kernels/python3dbg
  ssh__sshhost06test001                            /Users/drs/Library/Jupyter/kernels/ssh__sshhost06test001
  ssh__sshhost06test002                            /Users/drs/Library/Jupyter/kernels/ssh__sshhost06test002
  ssh_host06_host06homehost06condaenvspy310-sshipy /Users/drs/Library/Jupyter/kernels/ssh_host06_host06homehost06condaenvspy310-sshipy
  bash$ 

The :code:`--no-check` (or alternatively :code:`-nc`) flag indicates that the validity of the kernel spec files
should **not** be checked. The :code:`-a` (or :code:`--all`) flag indicates that it should show **all** kernel
specifications rather than just the ones for `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ or
:code:`sshpyk` kernel specification files.


Command line "ls" options
-------------------------

The following options are available for listing the Jupyter kernel specifications:

.. option::   **--help, -h**

              Show this help message and exit.

.. option::   **--all, -a**

              List all kernels that are available rather than just
              `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ and sshpyk kernels.

.. option::   **--local, -l**

              Only list the information for the local Python executable.

.. option::   **--remote, -r**

              Only list the information for the remote Python executable.
              
.. option::  **--no-check, -nc**

              Do not check for the existence local or remote Python executables. This option
              can be used alone or with other options, e.g. with :code:`-l`.
