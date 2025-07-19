import logging
import time
import threading
import serial
from serial.tools import list_ports


class PicoSerialHandler:
    def __init__(self, worker):
        self.worker = worker

    def _find_pico_port(self):
        for port in list_ports.comports():
            try:
                if "pico" in port.description.lower():
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
