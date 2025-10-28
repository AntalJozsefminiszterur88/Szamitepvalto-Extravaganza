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
For troubleshooting, you can enable verbose logging by changing the `level`
argument of `logging.basicConfig` to `DEBUG` in `main.py`. Log entries are
stored in the `logs` directory beside the executable with automatic rotation.

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

The software now follows a centralized control model. The EliteDesk runs the
controller (`ado`) service and acts as the single decision point. The desktop
machine is configured as an `input_provider` that forwards physical keyboard and
mouse events only when instructed, while the laptop continues to operate as a
simple `vevo` receiver. This keeps local control snappy and avoids sending
unnecessary traffic across the network when you are working on the desktop
itself.

### Shared clipboard

The controller maintains a shared clipboard for every connected client. Long
text snippets and full-resolution images copied on any machine are packaged in
their native Windows clipboard formats and distributed to all other peers. The
receiving side updates its local clipboard immediately so the content can be
used without any extra steps. Clipboard entries that remain unchanged for more
than 12 hours are cleared automatically to avoid stale data lingering in the
shared history.

### Automatic connection

The receiver continuously searches for the host using Zeroconf and
also retries the last known IP address. This means that whether the
host or any receiver is powered on first, they will automatically find
each other and connect once both sides are running. If the connection
is interrupted on either side, both peers keep searching and will
reconnect automatically as soon as the other becomes available again.

The EliteDesk controller accepts connections from both the desktop input provider and any
remote receivers. The desktop streams keyboard and mouse events only when the controller
explicitly instructs it to do so, ensuring there is no unnecessary network traffic while
you are working locally. When control is transferred to the EliteDesk the monitor input is
switched to the secondary HDMI port, and it is switched back to HDMI1 as soon as you return
to the desktop. Switching to the laptop never touches the monitor input.

### Controller hotkeys

While running on the EliteDesk controller you can switch targets either with the Pico
hardware buttons (F13–F15) or by using the keyboard hotkeys:

- **Shift + Numpad 0 / F13** – Return control to the desktop input provider
- **Shift + Numpad 1 / F14** – Route control to the laptop client (no monitor switch)
- **Shift + Numpad 2 / F15** – Take control of the EliteDesk itself and switch the monitor to HDMI2
- **F17** – Manually switch the primary monitor input to HDMI2 without changing the active client

The controller always returns to the desktop before activating a different remote target so
that the monitor state remains consistent.

Slow clients that cannot keep up with the stream are disconnected after a short
send timeout so they no longer cause lag for others. Input events are queued up
to a limited size and older ones are discarded if necessary. The application
also attempts to run with high process priority for smoother forwarding.

### Debug logging

For troubleshooting, enable verbose debug logging by editing `main.py` and
setting the log level to `DEBUG`. Messages will appear in the console and in
`logs/kvm_app.log` with rotation. This includes detailed information about
hotkey detection, network activity and event forwarding.

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
you can verify detection in the console. The same manager also captures the F13
to F17 keys when pressed on any attached keyboard, so the hardware buttons and
manual shortcuts share a single handling path.

### CircuitPython HID script

The `pico_hid_switch.py` example runs directly on the Pico. It emulates the
hotkey presses for switching computers by sending the F13–F16 keys as a USB HID
keyboard. The desktop application's button manager listens for these key events
alongside regular keyboards and routes them to the right action immediately.

If both the console and data CDC interfaces are enabled, Windows will expose two
COM ports. The optional serial protocol still expects the **data** interface, so
ensure this port is available or disable the console interface in `boot.py` to
avoid connecting to the wrong one. After copying `boot.py` to the Pico you must
reset the board for the new configuration to take effect.

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

A simple script `utils/clipboard_sync.py` is provided to share the system clipboard between computers.
One machine runs the server:

```bash
python utils/clipboard_sync.py server --port 8765
```

Other machines connect as clients:

```bash
python utils/clipboard_sync.py client <server-ip> --port 8765
```

Whenever the clipboard changes on any connected computer the new contents are sent to all others.
The script relies on the `pyperclip` library for cross-platform clipboard access.
Install it with `pip install pyperclip`. On Linux, `pyperclip` also depends on
either `xclip` or `xsel` (or `wl-clipboard` for Wayland) being available.
Without these the script may not be able to read or write the clipboard.

On Windows the helper taps into the native Win32 clipboard so that full fidelity
image data (including PNG, JPEG, GIF and large 10+ MiB screenshots) and file
collections can be mirrored as well. File selections are packaged into a
temporary ZIP archive, streamed across the network and unpacked on the receiver
into a throwaway directory before being re-published as a standard
`CF_HDROP` payload. This allows copying complex document sets exactly as if they
originated locally, while still keeping the text-based pyperclip fallback for
other platforms.

## Formatting

Code style checks can be performed with `pycodestyle`:

```bash
pycodestyle --max-line-length=120 gui.py utils/clipboard_sync.py
```

You can also use the provided configuration in `setup.cfg` to keep
lines under 120 characters.

## Cleaning up

Before committing, remove Python bytecode caches to keep the repository small:

```bash
find . -name '__pycache__' -type d -exec rm -r {} +
```

These directories are already ignored via `.gitignore` and won't be tracked by Git.
