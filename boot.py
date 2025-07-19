import usb_hid
import usb_cdc

usb_hid.enable((usb_hid.Device.KEYBOARD,))
usb_cdc.enable(console=True, data=True)
