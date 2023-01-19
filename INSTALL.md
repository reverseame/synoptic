# server-tracer module

## Linux

1. Export the following variable in your `.bashrc` file:

```Bash
export PIN_ROOT="/absolute/path/to/pin-3.25"
```

2. Run `make` in `protocol-modeler/server-tracer/` folder. It will create the `server-tracer.so` Pintool under `obj-intel64` folder (or `obj-ia32` in 32-bits systems)

3. You can now run the Pintool with:

```console
$ $PIN_ROOT/pin -follow_execv -t /absolute/path/to/protocol-modeler/server-tracer/obj-intel64/server-tracer.so [options] -- server-executable [args]
```

## Windows

1. Copy [server-tracer](server-tracer) folder to `%PIN_ROOT%\source\tools`
2. Open [server_tracer.vcxproj](server-tracer/server_tracer.vcxproj) of copied folder with Vistual Studio
3. Select _Release x86/x64_ option and build the Pintool with _Build_ > _Build Solution_. This will create the Pintool DLL in the corresponding folder (x64/x86 under Release folder)
4. Run Pintool with:

```console
> %PIN_ROOT%\pin.exe -follow_execv -t %PIN_ROOT%\source\tools\server-tracer\x64\Release\server-tracer.dll [options] -- server-executable [args]
```

# trace-modeler module

You only need to install the [requirements.txt](trace-modeler/requirements.txt) file:

```console
$ python -m pip install -r requirements.txt
```

Optionally, you can install dependencies in a virtual environment:

```
$ python -m venv virtualenv
$ source virtualenv/bin/activate
(virtualenv) $ python -m pip install -r requirements.txt
```