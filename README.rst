Remote Jupyter Kernels via SSH
******************************

Launch and connect securely to Jupyter kernels on remote machines via SSH with minimal
configuration, as if they were local.

ℹ️ Note
  Currently, Windows is not supported as neither local nor remote machine.

Table of Contents
=================

- `Quick Start`_
- `Installation`_
- `Managing SSH Jupyter Kernels Specifications`_

  * `Listing Available Kernels`_
  * `Adding a Remote Kernel`_
  * `Editing an Existing Kernel`_
  * `Deleting a Kernel`_

- `SSH Configuration`_

  * `Understanding SSH Host Aliases`_
  * `Recommended SSH Config`_
  * `Authentication via Private/Public Key`_

    + `Alternatives to Private/Public Key Authentication`_

  * `Authentication via Password`_
  * `Using Bastion/Jump Hosts`_

- `Launching Remote Kernels from Command Line`_

  * `Kernel Persistence`_
  * `Interactive Controls`_
  * `Integration with Jupyter`_
  * `Programmatic Usage in Python`_

- `Development`_

  * `Run git hooks manually`_

- `Troubleshooting`_
- `Implementation Details`_
- `Historical Note`_

Quick Start
***********

Get up and running with sshpyk in minutes:

1. Install sshpyk on your local machine

.. code-block:: bash

  pip install sshpyk

See `Installation`_ for more details.

2. Add a **DEDICATED** alias configuration entry in your SSH ``config`` file (typically ``~/.ssh/config``) with the following settings:

.. code-block:: bash

  # You can name the alias anything you want. We recommend to include "sshpyk"
  # in the name to remind yourself that this is a DEDICATED alias for sshpyk.
  Host remote_server_sshpyk
    HostName 192.168.1.100 # EDIT THIS
    User my_user_name_on_remote_server # EDIT THIS
    IdentityFile ~/.ssh/private_key_for_remote_server # EDIT THIS
    # WARNING: ControlMaster/ControlPath/ControlPersist are mandatory and should be
    # under a *DEDICATED* host alias, otherwise you will experience bad side effects
    ControlMaster auto # must be `auto`
    ControlPath ~/.ssh/sshpyk_%r@%h_%p # dir must exit!
    ControlPersist 10m
    # Other recommended configurations
    StrictHostKeyChecking no
    ServerAliveInterval 5
    ServerAliveCountMax 120000
    TCPKeepAlive yes
    ConnectionAttempts 1
    ConnectTimeout 5

💡 Tip
  If you already have an ssh host alias configured. You can prefix your host alias name
  with a wildcard :code:`*` and then define a dedicated host alias prefixed
  with, e.g., ``_sshpyk`` as follows. (Make sure the wildcard does not match other hosts
  unintentionally!)

  .. code-block:: bash

    Host remote_server*
      HostName 192.168.1.100 # EDIT THIS
      User my_user_name_on_remote_server # EDIT THIS
      IdentityFile ~/.ssh/private_key_for_remote_server # EDIT THIS
      # Other recommended configurations
      StrictHostKeyChecking no
      ServerAliveInterval 5
      ServerAliveCountMax 120000
      TCPKeepAlive yes
      ConnectionAttempts 1
      ConnectTimeout 5

    # Inherits the rest of the config from `remote_server*`
    Host remote_server_sshpyk
      # WARNING: ControlMaster/ControlPath/ControlPersist are mandatory and should be
      # under a *DEDICATED* host alias, otherwise you will experience bad side effects
      ControlMaster auto # must be `auto`
      ControlPath ~/.ssh/sshpyk_%r@%h_%p # dir must exit!
      ControlPersist 10m

With this config you can ssh into your remote as usual with ``remote_server`` for all
the purposes you are already used to. While ``remote_server_sshpyk`` will be used
exclusively for ``sshpyk`` without interfering with your other ssh sessions.

See `Recommended SSH Config`_ for more details.

3. Ensure you have SSH access to your remote server and public key authentication is set up, you must connect without password prompt:

.. code-block:: bash

  ssh remote_server_sshpyk

See `Authentication via Private/Public Key`_ for setting up SSH keys.
If you are sure that the remote ``sshd`` does not allow authentication via private/public key see `Authentication via Password`_.

4. Add a remote kernel (replace values with your configuration):

.. code-block:: bash

  sshpyk add --ssh-host-alias remote_server_sshpyk \
              --kernel-name ssh_remote_python3 \
              --display-name "Remote Python 3.10" \
              --remote-python-prefix /path/to/python/env \
              --remote-kernel-name python3 \
              --language python

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
* On the remote system: ``jupyter_client``

Managing SSH Jupyter Kernels Specifications
*******************************************

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
  Name:                  demo_remote
  Display Name:          Python 3.9 (Remote Demo)
  Kernel spec:           /Users/victor/Library/Jupyter/kernels/demo_remote/kernel.json
  Command (simplified):  ssh sshpyk_mba sshpyk-kernel --SSHKernelApp.kernel_name=python3 ...
  Language:              python
  Interrupt Mode:        (v) message
  SSH Path:              (v) /opt/homebrew/bin/ssh
  SSH Host Alias:        sshpyk_mba
                            (i) user: victor
                            (i) hostname: sshpyk_mba
                            (v) identityfile: /Users/victor/.ssh/id_rsa_for_sshpyk
                            (v) controlmaster: auto
                            (v) controlpersist: 600
                            (v) controlpath: /Users/victor/.ssh/sshpyk_victor@192.168.238.4_22
                            (i) proxyjump: sshpyk_jump
  SSH Host Alias:        sshpyk_jump (jump)
                            (i) user: root
                            (i) hostname: sshpyk_jump
                            (v) identityfile: /Users/victor/.ssh/id_rsa_for_sshpyk_jump
                            (v) controlmaster: auto
                            (v) controlpersist: 600
                            (v) controlpath: /Users/victor/.ssh/sshpyk_root@81.82.23.179_53456
  SSH Connection:        (v) sshpyk_mba
  Remote System:         Darwin MacBook-Air 20.5.0 Darwin Kernel Version 20.5.0: Sat May  8 05:10:33 PDT 2021; root:xnu-7195.121.3~9/RELEASE_X86_64 x86_64
  Remote Interrupt Mode: signal
  Remote Python:         (v) /usr/local/anaconda3/envs/f39/bin/python
  Remote Kernel Name:    (v) python3
  Launch Timeout:        15
  Shutdown Timeout:      15
  Remote Command:        python -m ipykernel_launcher -f {connection_file}

  ----- SSH Kernel -----
  Name:                  ssh_mbp_ext
  Display Name:          Python 3.13 (RMBP)
  Kernel spec:           /Users/victor/Library/Jupyter/kernels/ssh_mbp_ext/kernel.json
  Command (simplified):  ssh sshpyk_mbp sshpyk-kernel --SSHKernelApp.kernel_name=python3 ...
  Language:              python
  Interrupt Mode:        (v) message
  SSH Path:              (v) /opt/homebrew/bin/ssh
  SSH Host Alias:        sshpyk_mbp
                            (i) user: victor
                            (i) hostname: sshpyk_mbp
                            (v) identityfile: /Users/victor/.ssh/id_rsa_for_sshpyk
                            (x) controlmaster: Must be 'auto', not 'true'.
                            (v) controlpersist: 600
                            (v) controlpath: /Users/victor/.ssh/sshpyk_victor@192.168.238.2_22
                            (!) proxycommand: ProxyCommand: ssh -W %h:%p sshpyk_jump, use ProxyJump instead.
  SSH Connection:        (v) sshpyk_mbp
  Remote System:         Darwin MacBook-Pro 22.6.0 Darwin Kernel Version 22.6.0: Thu Dec  5 23:40:09 PST 2024; root:xnu-8796.141.3.709.7~4/RELEASE_ARM64_T6000 arm64
  Remote Interrupt Mode: signal
  Remote Python:         (v) /opt/homebrew/anaconda3/envs/g/bin/python
  Remote Kernel Name:    (v) python3
  Launch Timeout:        15
  Shutdown Timeout:      15
  Remote Command:        python -m ipykernel_launcher -f {connection_file}

  13400 2025-05-13 17:43:48,886 ERROR    sshpyk.utils utils:274 verify_ssh_connection: SSH connection to 'mbp_ext' failed: raw_output = ''
  ----- SSH Kernel -----
  Name:                  ssh_mbp_ext_broken
  Display Name:          Python 3.13 (RMBP Broken)
  Kernel spec:           /Users/victor/Library/Jupyter/kernels/ssh_mbp_ext_broken/kernel.json
  Command (simplified):  ssh sshpyk_mbp_ext sshpyk-kernel --SSHKernelApp.kernel_name=python3 ...
  Language:              python
  Interrupt Mode:        (v) message
  SSH Path:              (v) /opt/homebrew/bin/ssh
  SSH Host Alias:        sshpyk_mbp_ext
                            (x) identityfile: Likely missing in your ssh config. Multiple values: ['~/.ssh/id_rsa', '~/.ssh/id_ecdsa', '~/.ssh/id_ecdsa_sk', '~/.ssh/id_ed25519', '~/.ssh/id_ed25519_sk', '~/.ssh/id_xmss'].
                            (i) user: victor
                            (x) hostname: Likely missing in your ssh config. host='sshpyk_mbp_ext' and hostname='sshpyk_mbp_ext' must be different.
                            (x) controlmaster: Must be 'auto', not 'false'.
                            (x) controlpersist: Must be, e.g., '10m' or 'yes', not 'no'.
                            (x) controlpath: Missing, use, e.g., '~/.ssh/sshpyk_%r@%h_%p'.
  SSH Connection:        (x) sshpyk_mbp_ext
  Remote Python:         (?) /opt/homebrew/anaconda3/envs/g/bin/python
  Remote Kernel Name:    (?) python3
  Launch Timeout:        15
  Shutdown Timeout:      15

Adding a Remote Kernel
======================

To add a new remote kernel, use the ``add`` command. For a remote kernel to work:

* ``sshpyk`` must be installed on the local system (which depends on ``jupyter_client`` explicitly)
* ``jupyter_client`` must be installed on the remote system

Here's the help information for the ``add`` command:

.. code-block:: bash

  $ sshpyk add --help

Editing an Existing Kernel
==========================

You can modify an existing kernel using the ``edit`` command:

.. code-block:: bash

  $ sshpyk edit --help

💡 Pro tip
  If you are familiar with Jupyter kernel specifications, you can edit the ``kernel.json``
  specifications manually in the ``Resource Dir`` for quick changes.

Deleting a Kernel
=================

To remove a kernel, use the ``delete`` command:

.. code-block:: bash

  $ sshpyk delete --help

SSH Configuration
*****************

Understanding SSH Host Aliases
==============================

The ``--ssh-host-alias`` parameter refers to host aliases defined in your SSH ``config`` file, **not** IP addresses.
These aliases, among other advantages, provide a convenient way to group connection
settings under a ``Host alias_name`` entry.
This simplifies making an SSH connection to just ``$ ssh alias_name`` and have the
SSH client use the settings defined under its ``Host alias_name`` entry.
For simplicity and maximum flexibility, ``sshpyk`` does not manage any of the SSH ``config`` options.
Instead we have a `Recommended SSH Config`_ below.

Recommended SSH Config
======================

Your SSH configuration is typically stored in ``$HOME/.ssh/config``.
We recommend a wildcard host alias and a **DEDICATED** host alias named such that it
matches the wildcard (or simply a dedicated host alias as shown in `Quick start`_):

.. code-block:: bash

  Host remote_server*
    # Required config: HostName/User/IdentityFile
    # ##################################################################################
    # IP address of the remote system
    HostName 192.168.1.100 # EDIT THIS
    # Your unix username on the remote system
    User my_user_name_on_remote_server # EDIT THIS
    # Required for automated login, see `Authentication via Private/Public Key`_
    # for more details
    IdentityFile ~/.ssh/private_key_for_remote_server # EDIT THIS
    # ##################################################################################

    # Connection stability:
    # ServerAliveInterval/ServerAliveCountMax/TCPKeepAlive/ConnectionAttempts/ConnectTimeout
    # ##################################################################################
    # Send a "heartbeat" to the server every ServerAliveInterval seconds, if no reply,
    # wait ServerAliveCountMax attempts before giving up.
    ServerAliveInterval 5
    # Set some big value, e.g. ServerAliveInterval * ServerAliveCountMax = ~7 days
    ServerAliveCountMax 120000
    TCPKeepAlive yes
    # Shorter ConnectionAttempts/ConnectTimeout helps to reconnect to the kernel faster
    # when e.g. loosing internet connection temporarily. However if connecting to your
    # remote host is expected to take a long time, you might need to increase these.
    ConnectionAttempts 1
    ConnectTimeout 5
    # ##################################################################################
    # The port on the remote system that SSH server is listening on (22 is the default)
    Port 22
    # Optional, slightly less secure but recommended for this type of automation:
    StrictHostKeyChecking no

    # ... rest of your config, if you know what you are doing

  # You can suffix the alias with anything you want. We recommend to include "sshpyk"
  # in the name to remind yourself that this is a dedicated alias for sshpyk.
  Host remote_server_sshpyk
    # Isolation, performance, responsiveness: ControlMaster/ControlPath/ControlPersist
    # ##################################################################################
    # Reuse existing connections to the remote server, this speeds up new connections
    # to the remote server by reusing a "master" connection. If a master connection
    # is already established, it will be used, otherwise a new one will be created.
    # `auto` option is also essential for reusing an ssh connection established manually
    # e.g. when the remote host requires a password and explicitly forbids private key
    # authentication.
    ControlMaster auto
    # The path to the control socket, this is used to manage the connection to the
    # remote server. Make sure to not use the same ControlPath for other host non-sshpyk
    # aliases! This is to avoid conflicts with other SSH connections and session to the
    # same machine. Sharing the same control socket with other non-sshpyk related SSH
    # sessions might have unintended side effects.
    # Make sure the dirs on the path to the control socket exist, otherwise unrelated
    # errors might happen in sshpyk.
    ControlPath ~/.ssh/sshpyk_%r@%h_%p
    # Keep the master connection "warm" after the last time the SSH connection was used.
    # For connection stability and to speed up kernel restarts.
    # Note that there will be some SSH process on your local machine still running for
    # after the kernel shutdown. This is expected and harmless.
    # When the remote host requires a password, set ControlPersist to a large value,
    # e.g. `200h` to avoid having to restart the master connection manually and input
    # the host password.
    ControlPersist 10m
    # ##################################################################################


With this configuration, you can use ``remote_server_sshpyk`` as your ``--ssh-host-alias`` in ``sshpyk`` commands.

⚠️ Warning
  Make sure that your alias name in the SSH ``config`` does not match any other alias
  "wildcards" in your SSH ``config`` unintentionally. For example, if you have an alias
  ``remote_*`` in your SSH ``config``, these settings can affect
  the ``remote_server_sshpyk`` as well, which might lead to unexpected behavior.

‼️ Important
  ``ControlMaster: auto`` is mandatory for ``sshpyk`` to work.
  We highly recommend using the suggested ``ServerAliveInterval``,
  ``ServerAliveCountMax``, ``TCPKeepAlive``, ``ControlPath``,
  and ``ControlPersist`` settings.
  This is to ensure that your SSH connection is stable and does not get dropped
  unexpectedly. With these settings your connection to the remote kernel should
  survive, e.g., losing your WiFi connection for a few minutes, and perhaps even
  longer.

Authentication via Private/Public Key
=====================================

``sshpyk`` expects ``ssh`` commands to run without password prompts.
We recommend using private/public key-based SSH authentication.
You must set up SSH key authentication for all remote hosts you intend to use.

To set up SSH key-based authentication:

1. Generate an SSH key pair on your local machine (if you don't already have one):

.. code-block:: bash

  ssh-keygen -t ed25519 -f ~/.ssh/private_key_for_remote_server -C "some comment for your own reference"

2. Copy your public key to the remote server:

.. code-block:: bash

  ssh-copy-id remote_username@some.remote.server.com

Or manually add the contents of ``~/.ssh/private_key_for_remote_server.pub`` from your local machine to ``~/.ssh/authorized_keys`` on the remote machine.

3. Add the key to your SSH config (edit to match your own setup):

.. code-block:: bash

  Host remote_server_sshpyk
    HostName some.remote.server.com
    User remote_username
    IdentityFile ~/.ssh/private_key_for_remote_server
    # ... the rest of the config as described in `Recommended SSH Config`

4. Test your connection, you should connect without being prompted for a password:

.. code-block:: bash

  ssh remote_server_sshpyk "sleep 1 && exit"

Alternatives to Private/Public Key Authentication
-------------------------------------------------

If the remote ``sshd`` is configured to specifically only allow password authentication,
you can still use ``sshpyk`` by either:

1. Changing the ``sshd`` configuration to allow private/public key-based authentication (ask your system administrator); or
2. Manually establishing a master SSH connection first, as described in `Authentication via Password`_; or
3. Spawning a ``sshd`` on the remote system on a custom port configured to allow private/public key-based authentication and following the instructions above.

Authentication via Password
===========================

If your remote host doesn't allow private/public key-based authentication and insists
on password authentication, you can still use ``sshpyk`` by manually establishing a
master SSH connection first:

1. In your SSH config, set a long ``ControlPersist`` value (or ``ControlPersist=yes`` for an indefinite persistence) to avoid frequent manual password prompts:

.. code-block:: bash

  Host sshpyk_password_server
    HostName password.example.com
    User remote-username
    ControlMaster auto
    ControlPath ~/.ssh/sshpyk_%r@%h_%p
    # Set a very long persistence time or ControlPersist=yes for indefinite persistence
    ControlPersist 200h
    # ... the rest of the config as described in `Recommended SSH Config`

2. Manually establish the master connection before attempting to start any ``sshpyk`` kernels:

.. code-block:: bash

  # -M = ControlMaster
  # -f = go to background
  # -N = do not execute a command on the remote server
  ssh -M -f -N sshpyk_password_server
  # You'll be prompted for your password

⚠️ Warning
  When using password authentication, if the master connection process dies,
  which happens if you disconnect from internet for a bit,
  you need to manually run ``ssh -M -f -N sshpyk_password_server`` again to input your password.
  Afterwards the connection to the remote kernel should be smoothly reestablished.

3. Now add and use your sshpyk kernel as normal, without needing to enter your password again:

.. code-block:: bash

  sshpyk add --ssh-host-alias sshpyk_password_server --kernel-name ssh_remote_python3 ...

The ``ControlMaster`` connection will remain active for the duration specified in ``ControlPersist``,
allowing ``sshpyk`` to use it seamlessly despite the password requirement.

Using Bastion/Jump Hosts
========================

One powerful SSH feature is the ability to connect to hosts behind a bastion (jump) server.
For example in your SSH config you would add the following **dedicated** alias entries:

.. code-block:: bash

  Host sshpyk_bastion
    HostName bastion.example.com
    User bastion-username
    IdentityFile ~/.ssh/id_rsa_bastion # required for automated login
    # ... the rest of the config as described in `Recommended SSH Config`

  Host sshpyk_internal_server
    HostName internal-server.example.com
    User remote-username
    IdentityFile ~/.ssh/id_rsa_internal # required for automated login

    ProxyJump sshpyk_bastion # this is the key line that enables the "jump" through the bastion
    # ... the rest of the config as described in `Recommended SSH Config`

‼️ Important
  For connection stability and performance, we highly recommend using the settings
  described in `Recommended SSH Config`_ along with using dedicated alias entries.

This configuration allows you to:

1. Connect first to ``bastion.example.com`` as ``bastion-username``
2. Then tunnel through to ``internal-server.example.com`` as ``remote-username``

When using ``sshpyk``, you would simply specify ``--ssh-host-alias sshpyk_internal_server``
and the SSH tunneling will be handled automatically according to your SSH ``config`` file.

‼️ Important
  Remember that SSH automatic authentication must be set up for both
  ``sshpyk_bastion`` and ``sshpyk_internal_server``, either via SSH private/public key-based
  authentication or password authentication, as described in `Authentication via Private/Public Key`_
  and `Authentication via Password`_, respectively.

💡 Tip
  You can of course have as many bastion hosts between you and the remote server as you want.

Launching Remote Kernels from Command Line
******************************************

The ``sshpyk-kernel`` command is a command-line utility to launch remote kernels and manage their lifecycle.
It uses the same provisioning system as the ``SSHKernelProvisioner`` but can be invoked directly to support use cases outside of Jupyter.

.. code-block:: bash

  $ sshpyk-kernel --help

When running in an interactive terminal, you can use ``Ctrl+D`` to show a menu to shutdown, interrupt, restart, or leave the command without shutting down the kernel.
More information will be printed in the logs when running the command.

Kernel Persistence
==================

The ``sshpyk-kernel`` command supports kernel persistence through the following options:

* ``--persistent``: If True, the remote kernel will be left running on shutdown so you can reconnect to it later.
* ``--persistent-file``: Path to save persistence info. If provided, ``--persistent`` is overridden to True. A default path will be used if not provided.
* ``--existing``: Connect to an existing kernel using a previously saved persistence info file.
* ``--leave``: Launch the kernel and exit command right away.

Example of creating a persistent kernel:

.. code-block:: bash

  # Create a persistent kernel
  sshpyk-kernel --kernel=demo_remote --persistent

Later, reconnect to the same kernel (the path will be printed in the logs of the previous command):

.. code-block:: bash

  sshpyk-kernel --kernel=demo_remote --existing=sshpyk-kernel-1c9ce85b-f722-41e5-970a-13cfdd44fbfb.json

ℹ️ Note
  ``--existing`` here is a path to a persistence file created by ``sshpyk-kernel``,
  **NOT** the typical jupyter connection file!

You can interact with the kernel using e.g. ``jupyter-console`` (a jupyter client launches an ``ipython`` shell):

.. code-block:: bash

  pip install jupyter-console # if not already installed
  jupyter-console --existing=kernel-a3b70f44-6b9a-4f82-a6b8-dd736f04b888.json

ℹ️ Note
  ``--existing`` here is a path to the local connection file, in the typical jupyter connection file format.
  It is **NOT** the persistence file created by ``sshpyk-kernel``.
  Similarly, this path is printed in the logs of the ``sshpyk-kernel`` command.

💡 Tip
  You can press ``Ctrl+D`` in the ``jupyter-console`` to leave the application without shutting down the kernel.
  Calling ``exit()``/``quit()`` in the ``ipython`` shell or a in notebook will still shutdown the kernel.
  This is expected behavior. The remote ``SSHKernelApp`` python script will detect this and shutdown itself.

Interactive Controls
====================

When running in an interactive terminal, you can use:

* ``Ctrl+D``: Shows a menu to interrupt, shutdown, restart, or leave the command without shutting down the kernel
* ``Ctrl+C``: Interrupts the kernel
* ``Ctrl+\`` (backslash): Leaves the application without shutting down the kernel

If you invoke ``sshpyk-kernel`` from a non-interactive shell, you can use signals to control the kernel:

* ``SIGTERM``: Shuts down the kernel, unless ``--persistent`` or ``--persistent-file`` have been passed
* ``SIGHUP``: Shuts down the kernel, unless ``--persistent`` or ``--persistent-file`` have been passed
* ``SIGINT``: Interrupts the kernel
* ``SIGUSR1``: Restarts the kernel
* ``SIGUSR2``: Shuts down the remote kernel, ignoring ``--persistent`` or ``--persistent-file``
* ``SIGQUIT``: Leaves the application without shutting down the kernel

* ``SIGKILL``: this signal cannot be caught, it will kill the local command without any local nor remote cleanup. Not recommended. Use only as last resort.

Integration with Jupyter
=======================

The command is designed to work with Jupyter's kernel specification system.
When you add a remote kernel using ``sshpyk add``, the command is automatically configured in the kernel spec file (``kernel.json``).
This allows applications external to Jupyter the jupyter ecosystem to launch the remote kernel and connect to it.

Example ``kernel.json`` created by ``sshpyk add``:

.. code-block:: json

  {
    "argv": [
      "/opt/homebrew/anaconda3/envs/g/bin/python",
      "/opt/homebrew/anaconda3/envs/g/bin/sshpyk-kernel",
      "--SSHKernelApp.kernel_name=demo_remote",
      "--KernelManager.connection_file='{connection_file}'"
    ],
    "display_name": "Python 3.9 (Remote Demo)",
    "language": "python",
    "interrupt_mode": "message",
    "metadata": {
      "kernel_provisioner": {
        "provisioner_name": "sshpyk-provisioner",
        "config": {
          "ssh": null,
          "ssh_host_alias": "sshpyk_mba",
          "remote_python": "/usr/local/anaconda3/envs/f39/bin/python",
          "remote_kernel_name": "python3"
        }
      }
    }
  }

Programmatic Usage in Python
============================

The ``demo.py`` in the repository provides a complete example of how to use ``sshpyk`` programmatically:

1. Launch a (persistent) remote kernel
2. Execute interactive code on it
3. Reconnect to the same kernel later
4. Clean up resources

For more information on interacting with the kernel programmatically,
see the `jupyter_client documentation <https://jupyter-client.readthedocs.io/>`_
or consult the ``provisioning.py`` source code for some inspiration.

Development
***********

In a Python 3.8+ environment:

1. ``pip install -e ".[dev]"`` # installs the python package in editable mode
2. Reload your shell, e.g. open the terminal again.
3. ``pre-commit install``
4. Make your changes to the files and test them.
5. ``git commit -m "your message"``, this will run the pre-commit hooks defined in ``.pre-commit-config.yaml``. If your code has problems it won't let you commit.

Run git hooks manually
======================

To auto-format code, apply other small fixes (e.g. trailing whitespace) and to lint all the code:

.. code-block:: bash

  pre-commit run --all-files

Troubleshooting
===============

If you are running into issues, try first to restart your system 😉.

Make sure you can ``ssh remote_server_sshpyk "sleep 1 && exit"`` into your remote host without password prompts,
before attempting to launch the ``sshpyk`` kernel.

To debug problems during kernel launch/shutdown/restart/etc., you can launch the sshpyk kernel manually with verbose logging:

.. code-block:: bash

  sshpyk-kernel --kernel ssh_remote_python3 --debug

Read the logs, it will contain commands and output from the local/remote processes.
You can open a new GitHub issue and share the output if you need help.

Implementation Details
======================

``sshpyk`` integrates with Jupyter Client through the kernel provisioning API introduced in ``jupyter_client`` 7.0.
It implements a custom ``KernelProvisionerBase`` subclass called ``SSHKernelProvisioner`` that:

1. Establishes SSH connections to remote hosts
2. Copies the ``sshpyk-kernel`` launcher script to the remote (by default into ``$HOME/.ssh/sshpyk/``, shell variables are expanded)
3. Launches kernels on remote systems
4. Sets up port forwarding for kernel communication channels using ``ssh -O forward -L ...`` control master commands
5. Manages the lifecycle of the remote kernel

The provisioner is registered as an entry point in ``pyproject.toml``, making it available to any
Jupyter application that uses ``jupyter_client``.

Historical Note
===============

The design of this package was initially inspired upon `SSH Kernel <https://github.com/bernhard-42/ssh_ipykernel>`_ which
in turn is based upon `remote_ikernel <https://bitbucket.org/tdaff/remote_ikernel>`_. This implementation was
created to adapt to recent changes to ``jupyter_client`` (which broke ``ssh_ipykernel``)
and to support Python 3.10+. Later it was reimplemented to integrate with ``jupyter_client``'s provisioning system.
