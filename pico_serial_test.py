import logging
import time
import serial
from serial.tools import list_ports


def find_pico_port():
    """Return the device path of a connected Pico if available."""
    keywords = ("pico", "circuitpython")
    data_candidate = None
    for port in list_ports.comports():
        try:
            desc_raw = port.description or ""
            manuf_raw = getattr(port, "manufacturer", "") or ""
            iface_raw = getattr(port, "interface", "") or ""
            desc = desc_raw.lower()
            manuf = manuf_raw.lower()
            iface = iface_raw.lower()
            vid = getattr(port, "vid", None)
            if (
                vid in (0x2E8A, 0x239A)
                or any(k in desc for k in keywords)
                or any(k in manuf for k in keywords)
            ):
                if "data" in iface or "data" in desc:
                    return port.device
                if not data_candidate:
                    data_candidate = port.device
        except Exception:
            continue
    return data_candidate


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.info("Starting Pico button test")
    while True:
        port_name = find_pico_port()
        if not port_name:
            logging.info("No Pico detected, retrying in 5s...")
            time.sleep(5)
            continue
        logging.info("Using Pico port %s", port_name)
        try:
            with serial.Serial(port_name, 9600, timeout=1) as ser:
                logging.info("Listening for button presses...")
                ser.reset_input_buffer()
                while True:
                    data = ser.read(1)
                    if not data:
                        continue
                    data = data.strip()
                    if not data:
                        continue
                    try:
                        char = data.decode("utf-8")
                    except Exception:
                        logging.warning("Received undecodable data: %r", data)
                        continue
                    logging.info("Button code received: %s", char)
        except serial.SerialException as exc:
            logging.warning("Serial connection error: %s", exc)
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
