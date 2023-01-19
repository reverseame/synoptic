Guide to install and use some server examples to be analyzed with `protocol-modeler`.

# SSH

## WolfSSH - working

Install at least this dependency:

```console
$ sudo apt install libtool
```

First, install WolfSSL in `/usr/local/`:

```console
$ git clone --depth 1 --branch v5.5.4-stable https://github.com/wolfSSL/wolfssl
$ cd wolfssl
$ ./configure --enable-keygen --enable-ocsp --enable-ssh
$ make check
$ sudo make install
```

You can skip the last step to not to install WolfSSL system-wide and link WolfSSH with the libraries placed at `wolfssl-5.5.4/src/.libs`. After WolfSSL compilation, build WolfSSH:

```console
$ git clone --depth 1 --branch v1.4.12-stable https://github.com/wolfSSL/wolfssh
$ cd wolfssh
$ ./autogen.sh
$ ./configure --with-wolfssl=/usr/local --enable-shell
$ make
$ make check
```

You can now analyze the WolfSSH server under `server-tracer`:

```console
$ $PIN_ROOT/pin -follow_execv -t /path/to/protocol-modeler/server-tracer/obj-intel64/server_tracer.so -debug -log /tmp/trace.log -- /path/to/wolfssh/examples/echoserver/echoserver -P <user>:<password>
```

`<user>` and `<password>` must be a valid session in your system. You can now interact with the server under analysis with:

```console
$ ssh <user>@localhost -p 22222
wolfSSH Example Echo Server
<user>@localhost's password: 
```

## OpenSSH - failing

In order to analyze OpenSSH server under Pin, we need to disable the sandboxing in the child processes. You need to satisfy some dependences:

```Shell
$ sudo apt install autoconf
$ sudo apt install libssl-dev
$ sudo apt install libpam0g-dev
```

And now you can use the following configuration:

```Shell
$ git clone --depth 1 --branch V_9_1_P1 https://github.com/openssh/openssh-portable
$ cd openssh-portable
$ autoreconf
$ ./configure --with-sandbox=no --with-pam
$ make
```

Now you have to set up all configuration in order to run sshd without root:

```Shell
$ sudo mkdir -p /opt/ssh
$ sudo chown [user]:[user] /opt/ssh
$ cp scp sftp sftp-server ssh ssh-add ssh-agent sshd ssh-keygen ssh-keyscan ssh-keysign ssh-pkcs11-helper ssh-sk-helper /opt/ssh/   # copy all binaries
$ cp sshd_config /opt/ssh
$ /opt/ssh/bin/ssh-keygen -q -N "" -t rsa -b 4096 -f /opt/ssh/ssh_host_rsa_key
$ /opt/ssh/bin/ssh-keygen -q -N "" -t ecdsa -f /opt/ssh/ssh_host_ecdsa_key
$ /opt/ssh/bin/ssh-keygen -q -N "" -t ed25519 -f /opt/ssh/ssh_host_ed25519_key
$ chmod 600 /opt/ssh/*              # only readeable to <user>
$ chmod 644 /opt/ssh/sshd_config    # readable to all users
```

Change `sshd_config`:

```Shell
$ vim /opt/ssh/sshd_config
[...]
Port 2222
[...]
HostKey /opt/ssh/ssh_host_rsa_key
HostKey /opt/ssh/ssh_host_ecdsa_key
HostKey /opt/ssh/ssh_host_ed25519_key
[...]
UsePAM yes
[...]
PidFile /opt/ssh/sshd.pid
[...]
Subsystem       sftp    /opt/ssh/sftp-server
```

You can now analyze the OpenSSH server under `server-tracer`:

```console
$PIN_ROOT/pin -follow_execv -t /path/to/protocol-modeler/server-tracer/obj-intel64/server_tracer.so -debug -log /tmp/trace.log -- /opt/ssh/sshd -f /opt/ssh/sshd_config -D -ddd
```

Due to OpenSSH not running as `root`, we can only log in to `<user>` in the system. You can now interact with the server under analysis with:

```console
$ ssh <user>@localhost -p 2222
(<user>@localhost) Password: 
```

# FTP

## ProFTPD - working

Download and compile:

```console
$ git clone --depth 1 --branch v1.3.8 https://github.com/proftpd/proftpd/ proftpd-1.3.8
$ cd proftpd-1.3.8
$ ./configure
$ make 
```

Configure ProFTPD server with `proftpd.conf` file:

```console
$ sudo mkdir -p /usr/local/var/
$ cp ./sample-configurations/basic.conf proftpd.conf
$ vim proftpd.conf
[...] Eliminate Anonymous section [...]
```

You can now analyze ProFTPD server under `server-tracer`:

```
$ sudo /opt/pin-3.25/pin -follow_execv -- /path/to/proftpd-1.3.8/proftpd -c /path/to/proftpd-1.3.8/proftpd.conf -n -X -d 10
```

## vsftpd - failing

Download and compile:

```console
$ wget https://security.appspot.com/downloads/vsftpd-3.0.5.tar.gz
$ tar xvfz vsftpd-3.0.5.tar.gz
$ cd vsftpd-3.0.5
$ make
```

Configure vsftpd server with `vsftpd.conf` file:

```console
$ cp ./EXAMPLE/INTERNET_SITE/vsftpd.conf .
$ vim vsftpd.conf
[...]
anonymous_enable=NO
[...]
local_enable=YES
[...]
#one_process_model=YES
[...]
$ sudo chown root:root vsftpd.conf
```

You can now analyze `vsftpd` server under `server-tracer`:

```console
$ sudo PIN_ROOT/pin -follow_execv -t /path/to/protocol-modeler/server-tracer/obj-intel64/server_tracer.so -debug -log /tmp/trace.log -- /path/to/vsftpd /path/to/vsftpd.conf
```