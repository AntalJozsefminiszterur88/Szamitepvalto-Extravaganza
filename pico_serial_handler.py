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
        candidates = []
        for port in list_ports.comports():
            try:
                desc = (port.description or "").lower()
                manuf = (getattr(port, "manufacturer", "") or "").lower()
                vid = getattr(port, "vid", None)
                if vid in (0x2E8A, 0x239A):
                    return port.device
                if any(k in desc for k in keywords) or any(k in manuf for k in keywords):
                    return port.device
                candidates.append((vid, desc, manuf))
            except Exception:
                continue
        for vid, desc, manuf in candidates:
            logging.debug(
                "Checked serial port VID=%s DESC='%s' MANUF='%s'",
                f"0x{vid:04X}" if vid else "None",
                desc,
                manuf,
            )
        return None

    def run(self):
        """Monitor the Pico serial connection and trigger worker actions."""
        logging.info("PicoSerialHandler thread started")
        while self.worker._running:
            port_name = self._find_pico_port()
            if not port_name:
                logging.info("No Pico detected")
                for _ in range(5):
                    if not self.worker._running:
                        logging.info("PicoSerialHandler stopping - worker ended")
                        return
                    time.sleep(1)
                continue

            logging.info("Pico found on %s", port_name)
            try:
                with serial.Serial(port_name, 9600, timeout=1) as ser:
                    logging.info("Connection to Pico active")
                    while self.worker._running:
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
        logging.info("PicoSerialHandler thread exiting")
