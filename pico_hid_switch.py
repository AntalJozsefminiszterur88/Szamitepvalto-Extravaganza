import time
import board
import digitalio
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keycode import Keycode

# Initialize the keyboard device
kbd = Keyboard(usb_hid.devices)

# Configure pins for the three buttons
button1_pin = digitalio.DigitalInOut(board.GP16)
button1_pin.direction = digitalio.Direction.INPUT
button1_pin.pull = digitalio.Pull.DOWN

button2_pin = digitalio.DigitalInOut(board.GP17)
button2_pin.direction = digitalio.Direction.INPUT
button2_pin.pull = digitalio.Pull.DOWN

button3_pin = digitalio.DigitalInOut(board.GP15)
button3_pin.direction = digitalio.Direction.INPUT
button3_pin.pull = digitalio.Pull.DOWN

print("Pico KVM Remote (HID Mode) is running...")

while True:
    if button1_pin.value:
        # Switch to host (Shift + Numpad 0)
        kbd.press(Keycode.SHIFT, Keycode.KEYPAD_ZERO)
        time.sleep(0.1)
        kbd.release_all()
        while button1_pin.value:
            time.sleep(0.01)

    if button2_pin.value:
        # Switch to laptop (Shift + Numpad 1)
        kbd.press(Keycode.SHIFT, Keycode.KEYPAD_ONE)
        time.sleep(0.1)
        kbd.release_all()
        while button2_pin.value:
            time.sleep(0.01)

    if button3_pin.value:
        # Switch to EliteDesk (Shift + Numpad 2)
        kbd.press(Keycode.SHIFT, Keycode.KEYPAD_TWO)
        time.sleep(0.1)
        kbd.release_all()
        while button3_pin.value:
            time.sleep(0.01)

    time.sleep(0.1)
