# pico_hid_switch.py - VÉGLEGES HID VERZIÓ (F13-F16 billentyűkkel)

import time
import board
import digitalio
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode

# Billentyűzet eszköz inicializálása
kbd = Keyboard(usb_hid.devices)

# --- Gombok beállítása a helyes, Pull.UP logikával ---
# Feltételezi, hogy a gombok a GPIO pin és a GND közé vannak kötve.

# Gomb 1 (Asztal / Host) -> F13 billentyűt küld
button1_pin = digitalio.DigitalInOut(board.GP16)
button1_pin.direction = digitalio.Direction.INPUT
button1_pin.pull = digitalio.Pull.UP

# Gomb 2 (Laptop) -> F14 billentyűt küld
button2_pin = digitalio.DigitalInOut(board.GP17)
button2_pin.direction = digitalio.Direction.INPUT
button2_pin.pull = digitalio.Pull.UP

# Gomb 3 (EliteDesk) -> F15 billentyűt küld
button3_pin = digitalio.DigitalInOut(board.GP15)
button3_pin.direction = digitalio.Direction.INPUT
button3_pin.pull = digitalio.Pull.UP

# ÚJ GOMB: Gomb 4 (Monitor HDMI-1) -> F16 billentyűt küld
button4_pin = digitalio.DigitalInOut(board.GP1)
button4_pin.direction = digitalio.Direction.INPUT
button4_pin.pull = digitalio.Pull.UP

print("Pico KVM Remote (HID F-Key Mode) is running...")

while True:
    # Mivel Pull.UP-ot használunk, a gombnyomást a 'False' állapot jelzi (if not ...)

    # 1. Gomb (GP16)
    if not button1_pin.value:
        print("Gomb 1 (GP16) lenyomva -> F13 küldése...")
        kbd.press(Keycode.F13)
        time.sleep(0.1)
        kbd.release_all()
        # Várunk, amíg a gombot elengedik
        while not button1_pin.value:
            time.sleep(0.01)

    # 2. Gomb (GP17) - A felcserélt logika szerint a Laptop
    if not button2_pin.value:
        print("Gomb 2 (GP17) lenyomva -> F14 küldése...")
        kbd.press(Keycode.F14)
        time.sleep(0.1)
        kbd.release_all()
        while not button2_pin.value:
            time.sleep(0.01)

    # 3. Gomb (GP15) - A felcserélt logika szerint az EliteDesk
    if not button3_pin.value:
        print("Gomb 3 (GP15) lenyomva -> F15 küldése...")
        kbd.press(Keycode.F15)
        time.sleep(0.1)
        kbd.release_all()
        while not button3_pin.value:
            time.sleep(0.01)

    # 4. Gomb (GP1)
    if not button4_pin.value:
        print("Gomb 4 (GP1) lenyomva -> F16 küldése...")
        kbd.press(Keycode.F16)
        time.sleep(0.1)
        kbd.release_all()
        while not button4_pin.value:
            time.sleep(0.01)

    time.sleep(0.1)
