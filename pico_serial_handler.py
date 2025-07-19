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
                matched = False
                if vid in (0x2E8A, 0x239A) or any(k in desc for k in keywords) or any(k in manuf for k in keywords):
                    matched = True
                    if "data" in iface or "data" in desc:
                        return port.device
                    if not data_candidate:
                        data_candidate = port.device
                if not matched:
                    logging.debug(
                        "Port not matched: %s VID=%s DESC='%s' MANUF='%s'",
                        port.device,
                        f"0x{vid:04X}" if vid else "None",
                        desc_raw,
                        manuf_raw,
                    )
            except Exception:
                continue
        return data_candidate

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
                    ser.reset_input_buffer()
                    while self.worker._running:
                        data = ser.read(1)
                        if not data:
                            continue
                        data = data.strip()
                        if not data:
                            continue
                        try:
                            char = data.decode("utf-8")
                        except Exception:
                            logging.warning("Received undecodable data from Pico: %r", data)
                            continue
                        logging.info("Pico button pressed: %s", char)
                        if char == '1':
                            self.worker.deactivate_kvm(switch_monitor=True, reason="pico button 1")
                        elif char == '2':
                            self.worker.toggle_client_control('laptop', switch_monitor=False)
                        elif char == '3':
                            self.worker.toggle_client_control('elitedesk', switch_monitor=True)
                        else:
                            logging.debug("Unknown Pico input: %r", data)
            except serial.SerialException:
                logging.info("Pico disconnected")
                time.sleep(1)
        logging.info("PicoSerialHandler thread exiting")
