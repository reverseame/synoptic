# servertracer submodule

## Linux

1. Export the following variable in your `.bashrc` file:

```Bash
export PIN_ROOT="/absolute/path/to/pin-3.25"
```

2. Run `make` in `synoptic/servertracer/` folder. It will create the `server_tracer.so` pintool under `obj-intel64` folder (or `obj-ia32` in 32-bits systems)

3. You can now run the pintool with:

```console
$ $PIN_ROOT/pin -follow_execv -t /absolute/path/to/synoptic/servertracer/obj-intel64/server_tracer.so [options] -- server-executable [args]
```

## Windows

1. Copy [servertracer](synoptic/servertracer/) folder to `%PIN_ROOT%\source\tools`
2. Open [server_tracer.vcxproj](synoptic/servertracer/server_tracer.vcxproj) of the copied folder with Vistual Studio
3. Select _Release x86/x64_ option and build the Pintool with _Build_ > _Build Solution_. This will create the Pintool DLL in the corresponding folder (x64/x86 under Release folder)
4. Run Pintool with:

```console
> %PIN_ROOT%\pin.exe -follow_execv -t %PIN_ROOT%\source\tools\servertracer\x64\Release\server_tracer.dll [options] -- server-executable [args]
```

# tracemodeler submodule

You only need to install the [requirements.txt](requirements.txt) file:

```console
$ python -m pip install -r requirements.txt
```

Optionally, you can install dependencies in a virtual environment:

```console
$ python -m venv virtualenv
$ source virtualenv/bin/activate
(virtualenv) $ python -m pip install -r requirements.txt
```

Also, there are dependencies that need to be installed on your system because Python libraries rely on these system wide binaries. So, you will need to install them with your system distribution packages:

```console
$ sudo apt install graphviz
```

You will also need to install radare2 5.8.4:

```console
$ curl -Ls https://github.com/radareorg/radare2/releases/download/5.8.4/radare2-5.8.4.tar.xz | tar xJv
$ radare2-5.8.4/sys/install.sh
```
