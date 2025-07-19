import logging
import time
import serial
from serial.tools import list_ports


class PicoSerialHandler:
    def __init__(self, worker):
        self.worker = worker

    def _find_pico_port(self):
        """Return the device path of a connected Pico if available."""
        keywords = ("pico", "circuitpython")
        for port in list_ports.comports():
            try:
                desc = port.description.lower()
                manuf = (getattr(port, "manufacturer", "") or "").lower()
                if port.vid == 0x2E8A:
                    return port.device
                if any(k in desc for k in keywords) or any(k in manuf for k in keywords):
                    return port.device
            except Exception:
                continue
        return None

    def run(self):
        while True:
            port_name = self._find_pico_port()
            if not port_name:
                logging.info("Pico not found, scanning again...")
                time.sleep(5)
                continue

            logging.info("Pico found on %s", port_name)
            try:
                with serial.Serial(port_name, 9600, timeout=1) as ser:
                    logging.info("Connection to Pico active")
                    while True:
                        data = ser.read(1)
                        if not data:
                            continue
                        if data == b'1':
                            self.worker.deactivate_kvm(switch_monitor=True, reason="pico button 1")
                        elif data == b'2':
                            self.worker.toggle_client_control('laptop', switch_monitor=False)
                        elif data == b'3':
                            self.worker.toggle_client_control('elitedesk', switch_monitor=True)
            except serial.SerialException:
                logging.info("Pico disconnected")
                time.sleep(1)
