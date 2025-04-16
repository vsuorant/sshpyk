Remote Jupyter Kernels via SSH
##############################

Launch and connect securely to Jupyter kernels on remote machines via SSH with minimal
configuration, as if they were local.

Quick Start
***********

Get up and running with sshpyk in minutes:

1. Install sshpyk on your local machine

.. code-block:: bash

  pip install sshpyk

See `Installation`_ for more details.

2. Configure your SSH connection to the remote machine by adding or editing an alias in your SSH config (typically ``~/.ssh/config``), we recommend the following configuration:

.. code-block:: text

  Host remote_server_alias
    HostName 192.168.1.100 # EDIT THIS
    User my_user_name_on_remote_server # EDIT THIS
    IdentityFile ~/.ssh/private_key_for_remote_server # EDIT THIS
    StrictHostKeyChecking no
    ServerAliveInterval 10
    ServerAliveCountMax 60000
    TCPKeepAlive yes
    ControlMaster auto
    ControlPath ~/.ssh/cm_%r@%h_%p
    # ... the rest of your config, if any

See `Recommended SSH Config Setup`_ for more details.

3. Ensure you have SSH access to your remote server and public key authentication is set up, you must connect without password prompt:

.. code-block:: bash

  ssh remote_server_alias

See `Authentication Requirements`_ for setting up SSH keys.

4. Add a remote kernel (replace values with your configuration):

.. code-block:: bash

  sshpyk add --ssh-host-alias remote_server_alias \
              --kernel-name ssh_remote_python3 \
              --display-name "Remote Python 3.10" \
              --remote-python-prefix /path/to/python/env \
              --remote-kernel-name python3 \

See `Adding a Remote Kernel`_ for all available options.

5. Start JupyterLab and select your new remote kernel for a notebook/console:

.. code-block:: bash

  jupyter lab

6. Your code now runs on the remote server and your local notebook interfaces with it!

Installation
************

You can install sshpyk using pip:

.. code-block:: bash

  pip install sshpyk

For development installation:

.. code-block:: bash

  pip install -e ".[dev]"

Requirements:

* On the local system: ``sshpyk`` and ``jupyter_client``
* On the remote system: ``jupyter_client`` (which provides ``jupyter-kernel`` command)

Managing Jupyter Kernels
************************

``sshpyk`` provides a command-line interface to manage remote Jupyter kernels via SSH tunnels:

.. code-block:: bash

  $ sshpyk --help
  usage: sshpyk [-h] [--verbose] {list,add,edit,delete} ...

  Manage SSH Jupyter kernels (version 0.0)

  positional arguments:
    {list,add,edit,delete}
                          Command to execute
      list                List available kernels
      add                 Add a new SSH kernel
      edit                Edit an existing SSH kernel
      delete              Delete a kernel

  options:
    -h, --help            show this help message and exit
    --verbose, -v         Increase logs verbosity (-v for warning, -vv for info, -vvv for debug)

Listing Available Kernels
=========================

You can list all available kernels using the ``list`` command:

.. code-block:: bash

  $ sshpyk list --help
  usage: sshpyk list [-h] [--remote] [--local] [--no-check]

  options:
    -h, --help      show this help message and exit
    --remote, -r    List only remote SSH kernels
    --local, -l     List only local kernels
    --no-check, -n  Skip remote kernel checks

  $ sshpyk list
  ---- Local Kernel ----
  Name:                  f310
  Display Name:          Python 3.10
  Resource Dir:          /Users/victor/Library/Jupyter/kernels/f310
  Command:               /opt/homebrew/anaconda3/envs/f310/bin/python -m ipykernel_launcher -f {connection_file}
  Language:              python
  Interrupt Mode:        signal

  ---- Local Kernel ----
  Name:                  ir
  Display Name:          R
  Resource Dir:          /opt/homebrew/anaconda3/envs/g/share/jupyter/kernels/ir
  Command:               R --slave -e IRkernel::main() --args {connection_file}
  Language:              R
  Interrupt Mode:        signal

  ----- SSH Kernel -----
  Name:                  ssh_mbp_ext
  Display Name:          Python 3.13 (Remote MBP)
  Resource Dir:          /Users/victor/Library/Jupyter/kernels/ssh_mbp_ext
  Command (simplified):  ssh mbp_ext jupyter-kernel --KernelApp.kernel_name=python3 ...
  Language:              python
  Interrupt Mode:        (v) message
  SSH Host Alias:        (v) mbp_ext
  SSH Path:              (v) /opt/homebrew/bin/ssh
  Remote System:         Darwin MacBook-Pro 22.6.0 Darwin Kernel Version 22.6.0: Thu Dec  5 23:40:09 PST 2024; root:xnu-8796.141.3.709.7~4/RELEASE_ARM64_T6000 arm64
  Remote Interrupt Mode: signal
  Remote Python Prefix:  (v) /opt/homebrew/anaconda3/envs/g
  Remote Kernel Name:    (v) python3
  Launch Timeout:        15
  Shutdown Timeout:      15
  Remote Command:        python -m ipykernel_launcher -f {connection_file}

Adding a Remote Kernel
======================

To add a new remote kernel, use the ``add`` command. For a remote kernel to work:

* ``sshpyk`` must be installed on the local system (which depends on ``jupyter_client`` explicitly)
* ``jupyter_client`` must be installed on the remote system (which provides ``jupyter-kernel`` command)

Here's the help information for the ``add`` command:

.. code-block:: bash

  $ sshpyk add --help

Editing an Existing Kernel
==========================

You can modify an existing kernel using the ``edit`` command:

.. code-block:: bash

  $ sshpyk edit --help

Deleting a Kernel
=================

To remove a kernel, use the ``delete`` command:

.. code-block:: bash

  $ sshpyk delete --help

SSH Configuration Notes
***********************

Understanding SSH Host Aliases
==============================

The ``--ssh-host-alias`` parameter refers to host aliases defined in your SSH configuration, not IP addresses.
These aliases provide a convenient way to manage connections to remote systems.

ℹ️ Note
  Currently, Windows is not supported as neither local nor remote machine.

Recommended SSH Config Setup
============================

Your SSH configuration is typically stored in ``$HOME/.ssh/config``. We recommend an entry that looks like this:

.. code-block:: text

  Host remote_server_alias
    # Required config: HostName/User/IdentityFile
    # IP address of the remote system
    HostName 192.168.1.100
    # Your unix username on the remote system
    User my_user_name_on_remote_server
    # Required for automated login
    IdentityFile ~/.ssh/private_key_for_remote_server

    # The port on the remote system that SSH server is listening on (22 is the default)
    Port 22

    # Optional, slightly less secure but recommended for this type of automation:
    StrictHostKeyChecking no

    # Connection stability: ServerAliveInterval/ServerAliveCountMax/TCPKeepAlive
    # Send a "heartbeat" to the server every ServerAliveInterval seconds, if no reply,
    # wait ServerAliveCountMax attempts before giving up.
    ServerAliveInterval 10
    # Set some big value, e.g. ServerAliveInterval * ServerAliveCountMax = ~7 days
    ServerAliveCountMax 60000
    TCPKeepAlive yes

    # Optional, for extra performance: ControlMaster/ControlPath
    ControlMaster auto
    ControlPath ~/.ssh/cm_%r@%h_%p

    # ... the rest of your config, if any

‼️ Important
  We highly recommend using the suggested ``ServerAliveInterval``, ``ServerAliveCountMax`` and ``TCPKeepAlive`` settings.
  This is to ensure that your SSH connection is stable and does not get dropped unexpectedly.
  With these settings your connection to the remote kernel should survive, e.g.,
  losing your WiFi connection for a few minutes.

With this configuration, you can use ``remote_server_alias`` as your ``--ssh-host-alias`` in ``sshpyk`` commands.

Authentication Requirements
===========================

‼️ Important
  ``sshpyk`` only supports key-based SSH authentication. You must set up SSH key authentication
  for all remote hosts you intend to use.

To set up SSH key-based authentication:

1. Generate an SSH key pair on your local machine (if you don't already have one):

.. code-block:: bash

  ssh-keygen -t ed25519 -f ~/.ssh/private_key_for_remote_server -C "some comment for your own reference"

2. Copy your public key to the remote server:

.. code-block:: bash

  ssh-copy-id remote_username@some.remote.server.com

Or manually add the contents of ``~/.ssh/private_key_for_remote_server.pub`` from your local machine to ``~/.ssh/authorized_keys`` on the remote machine.

3. Add the key to your SSH config (edit to match your own setup):

.. code-block:: text

  Host remote_server_alias
    HostName some.remote.server.com
    User remote_username
    IdentityFile ~/.ssh/private_key_for_remote_server
    # ... the rest of your config

4. Test your connection, you should connect without being prompted for a password:

.. code-block:: bash

  ssh remote_server_alias

Advanced: Using Bastion/Jump Hosts
==================================

One powerful feature is the ability to connect to hosts behind a bastion (jump) server. For example in your SSH config:

.. code-block:: text

  Host bastion
    HostName bastion.example.com
    User bastion-username
    IdentityFile ~/.ssh/id_rsa_bastion # required for automated login
    # ... the rest of your config

  Host internal_server
    HostName internal-server.example.com
    User remote-username
    IdentityFile ~/.ssh/id_rsa_internal # required for automated login
    ForwardX11Trusted yes
    ProxyJump bastion # this is the key line that enables the "jump" through the bastion
    # ... the rest of your config

This configuration allows you to:

1. Connect first to ``bastion.example.com`` as ``bastion-username``
2. Then tunnel through to ``internal-server`` as ``remote-username``

When using sshpyk, you would simply specify ``--ssh-host-alias internal_server`` and the SSH tunneling
will be handled automatically according to your configuration.

‼️ Important
  Remember that SSH key-based authentication must be set up for both the bastion host and the internal server.

💡 Tip
  You can of course have as many bastion hosts between you and the remote server as you want.

Development
###########

In a Python 3.8+ environment:

1. ``pip install -e ".[dev]"`` # installs the python package in editable mode
2. Reload your shell, e.g. open the terminal again.
3. ``pre-commit install``
4. Make your changes to the files and test them.
5. ``git commit -m "your message"``, this will run the pre-commit hooks defined in ``.pre-commit-config.yaml``. If your code has problems it won't let you commit.

Run git hooks manually
**********************

To auto-format code, apply other small fixes (e.g. trailing whitespace) and to lint all the code:

.. code-block:: bash

  pre-commit run --all-files

Implementation Details
**********************

sshpyk integrates with Jupyter Client through the kernel provisioning API introduced in jupyter_client 7.0+.
It implements a custom ``KernelProvisionerBase`` subclass called ``SSHKernelProvisioner`` that:

1. Establishes SSH connections to remote hosts
2. Sets up port forwarding for kernel communication channels
3. Launches kernels on remote systems
4. Manages the lifecycle of remote kernels

The provisioner is registered as an entry point in ``pyproject.toml``, making it available to any
Jupyter application that uses ``jupyter_client``.

Historical Note
***************

The design of this package was initially inspired upon `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ which
in turn is based upon `remote_ikernel <https://bitbucket.org/tdaff/remote_ikernel>`_. This implementation was
created to adapt to recent changes to ``jupyter_client`` (which broke ``ssh_ipykernel``)
and to support Python 3.10+. Later it was reimplemented to integrate with ``jupyter_client``'s provisioning system.
