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
For troubleshooting, you can enable debug logging by setting the
`logging` level to `DEBUG` in `main.py`.

## Building a Windows executable

Use `build_exe.py` to create a standalone executable with PyInstaller. The script
packages the application with the `--windowed`/`--noconsole` flag so no console
window appears when the executable is launched:

```bash
python build_exe.py
```

The script ensures PyInstaller is installed and bundles `main.py` into a single
`exe` named `Szamitepvalto-Extravaganza.exe`. The icon from
`keyboard_mouse_switch_icon.ico` is included using the `--add-data` option so it
is available at runtime. By default the generated executable runs without
opening a console window.


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
application logs activity to the console and stores settings via
`QSettings`. Use the interface to configure host and client codes, select which
computer this instance represents (Desktop, Laptop or EliteDesk) and start or
stop the KVM service. The correct operating mode is selected automatically.

### Automatic connection

The receiver continuously searches for the host using Zeroconf and
also retries the last known IP address. This means that whether the
host or any receiver is powered on first, they will automatically find
each other and connect once both sides are running.

The desktop acting as the host can accept multiple client connections at once. Only the
selected receiver will get the forwarded input events. Switch targets with the hotkeys to
transfer control exclusively.

### Host hotkeys

While running on the desktop, use the following shortcuts to control the connected machines:

- **Shift + Numpad 1** – Take control of the laptop
- **Shift + Numpad 2** – Take control of the EliteDesk and switch the monitor input
- **Shift + Numpad 0** – Return control to the desktop and restore the monitor input

Switching directly between the laptop and EliteDesk is disabled. Press `Shift + Numpad 0` first to
return to the desktop before activating the other client.

Slow clients that cannot keep up with the stream are disconnected after a short
send timeout so they no longer cause lag for others. Input events are queued up
to a limited size and older ones are discarded if necessary. The application
also attempts to run with high process priority for smoother forwarding.

### Debug logging

For troubleshooting, enable verbose debug logging by editing `main.py` and
setting `logging.basicConfig(level=logging.DEBUG)`. Detailed information will
then appear in the console about hotkey detection, network activity and event
forwarding.

### System tray

When closing the main window with the **X** button the window is automatically
hidden and the application keeps running in the system tray. Use the tray icon
menu to restore or quit.

### Remote switching

When controlling the laptop, press **Ctrl + Shift + F12** to immediately switch
control to the EliteDesk. The laptop client sends a command back to the host,
which activates the EliteDesk as the new target.

### Pico hardware buttons

If a Raspberry Pi Pico or a compatible microcontroller is connected via USB,
the application monitors it with a dedicated background thread. Boards using
the Raspberry Pi VID ``0x2E8A`` or Adafruit's ``0x239A`` are detected
automatically. Button `1` returns control to the desktop, `2` selects the laptop
and `3` selects the EliteDesk. Connection and disconnection events are logged so
you can verify detection in the console.

### CircuitPython HID script

The `pico_hid_switch.py` example runs directly on the Pico. It emulates the hotkey
presses for switching computers and now opens the `usb_cdc` serial connection.
When a button is pressed the script writes `b'1'`, `b'2'` or `b'3'` to the serial
port and briefly pauses so the host receives the byte. The `PicoSerialHandler`
in the desktop application listens for these values to activate the appropriate
target.

If both the console and data CDC interfaces are enabled, Windows will expose two
COM ports. The application expects the **data** interface, so ensure this port is
available or disable the console interface in `boot.py` to avoid connecting to
the wrong one.

After copying `boot.py` to the Pico you must reset the board for the new
configuration to take effect.

### Autostart

On Windows the application configures autostart via the registry. When started
this way the program is launched with the ``--tray`` argument so it remains
hidden in the system tray. If a packaged executable is used the stored path now
points directly to the ``.exe`` with the same ``--tray`` flag. Disable the
option in the GUI to remove the entry. When launched from autostart the
application automatically activates the previously selected connection. In a
packaged build this autostart setting is also honoured when the ``.exe`` is
started manually, causing the window to stay in the tray and the previous
connection to activate immediately.

Every time the application starts it now refreshes the registry entry when
autostart is enabled, so the path always refers to the currently running
executable. This prevents console windows from appearing if the application was
packaged after enabling autostart from a normal Python interpreter.


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

## Formatting

Code style checks can be performed with `pycodestyle`:

```bash
pycodestyle --max-line-length=120 gui.py clipboard_sync.py
```

You can also use the provided configuration in `setup.cfg` to keep
lines under 120 characters.

## Cleaning up

Before committing, remove Python bytecode caches to keep the repository small:

```bash
find . -name '__pycache__' -type d -exec rm -r {} +
```

These directories are already ignored via `.gitignore` and won't be tracked by Git.
