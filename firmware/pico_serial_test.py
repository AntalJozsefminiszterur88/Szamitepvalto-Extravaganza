import time
import board
import digitalio
import usb_cdc

# GPIO button definitions using internal pull-ups
button1 = digitalio.DigitalInOut(board.GP16)
button1.direction = digitalio.Direction.INPUT
button1.pull = digitalio.Pull.UP

button2 = digitalio.DigitalInOut(board.GP17)
button2.direction = digitalio.Direction.INPUT
button2.pull = digitalio.Pull.UP

button3 = digitalio.DigitalInOut(board.GP15)
button3.direction = digitalio.Direction.INPUT
button3.pull = digitalio.Pull.UP

# New button on GP1 for switching monitor input
button4 = digitalio.DigitalInOut(board.GP1)
button4.direction = digitalio.Direction.INPUT
button4.pull = digitalio.Pull.UP

serial = usb_cdc.data

while True:
    if not button1.value:
        serial.write(b'1')
        time.sleep(0.1)
        while not button1.value:
            time.sleep(0.01)
    if not button2.value:
        serial.write(b'2')
        time.sleep(0.1)
        while not button2.value:
            time.sleep(0.01)
    if not button3.value:
        serial.write(b'3')
        time.sleep(0.1)
        while not button3.value:
            time.sleep(0.01)
    if not button4.value:
        serial.write(b'4')
        time.sleep(0.1)
        while not button4.value:
            time.sleep(0.01)
    time.sleep(0.1)
