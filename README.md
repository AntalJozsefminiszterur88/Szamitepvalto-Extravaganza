# KVM Switch Controller

This application provides a graphical user interface for controlling a keyboard
and mouse switch (KVM) between multiple computers. The GUI is built with
[PySide6](https://pyside.org/) and communicates over the network using
`zeroconf`. Hotkeys are monitored with `pynput` and monitor switching is handled
through `monitorcontrol`.

## Main entry point

Run the project by executing `main.py`:

```bash
python main.py
```

This starts the Qt based interface defined in `gui.py` and launches the
background worker defined in `worker.py` for handling networking and hotkeys.

## Building a Windows executable

Use `build_exe.py` to create a standalone executable with PyInstaller:

```bash
python build_exe.py
```

The script ensures PyInstaller is installed and bundles `main.py` into a single
`exe` named `Szamitepvalto-Extravaganza.exe`. The icon from
`keyboard_mouse_switch_icon.ico` is included using the `--add-data` option so it
is available at runtime. The console window is hidden on startup.

## Building a Linux executable

On Windows systems with the Windows Subsystem for Linux (WSL) installed you can
create a Linux binary using the `build_linux.bat` script:

```cmd
build_linux.bat
```

The batch file runs PyInstaller inside WSL and places the resulting executable
in the `dist` directory.

## Installation

Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

The main dependencies are:

- PySide6 – Qt GUI framework
- pynput – keyboard and mouse monitoring
- zeroconf – service discovery on the local network
- monitorcontrol – controlling monitor inputs

## Usage

After installing the dependencies, run `python main.py` to launch the GUI. The
application logs activity to `kvm_switch.log` and stores settings via
`QSettings`. Use the interface to configure host and client codes, select which
computer this instance represents (Desktop, Laptop or EliteDesk) and start or
stop the KVM service. The correct operating mode is selected automatically.

The desktop acting as the host now accepts multiple client connections simultaneously. All
connected receivers will get the forwarded input events.

### System tray

When closing the main window with the **X** button the window is automatically
hidden and the application keeps running in the system tray. Use the tray icon
menu to restore or quit.

### Remote switching

When controlling the laptop, press **Ctrl + Shift + F12** to immediately switch
control to the EliteDesk. The laptop client sends a command back to the host,
which activates the EliteDesk as the new target.

### Autostart

On Windows the application configures autostart via the registry. On Linux a
``.desktop`` entry is created under ``~/.config/autostart``. When started this
way the program is launched with the ``--tray`` argument so it remains hidden in
the system tray. If a packaged executable is used the stored path now points
directly to the ``.exe`` with the same ``--tray`` flag. Disable the option in
the GUI to remove the entry. When launched from autostart the application
automatically activates the previously selected connection. In a packaged build
this autostart setting is also honoured when the ``.exe`` is started manually,
causing the window to stay in the tray and the previous connection to activate
immediately.


## Clipboard synchronization

A simple script `clipboard_sync.py` is provided to share the system clipboard between computers.
One machine runs the server:

```bash
python clipboard_sync.py server --port 8765
```

Other machines connect as clients:

```bash
python clipboard_sync.py client <server-ip> --port 8765
```

Whenever the clipboard changes on any connected computer the new contents are sent to all others.
The script relies on the `pyperclip` library for cross-platform clipboard access.
