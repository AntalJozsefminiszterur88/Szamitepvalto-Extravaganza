# clipboard_sync.py
# Egy robusztus, hibatűrő wrapper a pyperclip köré.

import logging
import time
import pyperclip

# A pyperclip néha furcsa kivételeket dob, amik nem standard Exception-ök.
# Ezért egy nagyon széles körű hibakezelést alkalmazunk.
PyperclipException = getattr(pyperclip, "PyperclipException", Exception)


def safe_copy(text: str, retries: int = 3, delay: float = 0.1) -> None:
    """
    Biztonságos vágólapra másolás, ami többször is megpróbálja, ha hiba történik.
    """
    if not text:
        return
    for attempt in range(retries):
        try:
            pyperclip.copy(text)
            return  # Sikeres, kilépünk
        except PyperclipException as e:
            logging.warning(
                f"Clipboard copy failed (attempt {attempt + 1}/{retries}): {e}"
            )
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                logging.error("Failed to copy to clipboard after multiple retries.")
                # Opcionálisan itt dobhatnánk egy saját, kezelt kivételt.


def safe_paste() -> str | None:
    """
    Biztonságos beillesztés a vágólapról, ami kezeli a hibákat.
    Visszatér a szöveggel, vagy None-nal, ha nem sikerült.
    """
    try:
        content = pyperclip.paste()
        # Győződjünk meg róla, hogy stringet adunk vissza
        return str(content) if content is not None else None
    except PyperclipException as e:
        # A logban látott specifikus, de ártalmatlan hiba figyelmen kívül hagyása
        if (
            "Error calling OpenClipboard" in str(e)
            and "Der Vorgang wurde erfolgreich beendet" in str(e)
        ):
            logging.debug(f"Ignoring known harmless clipboard error: {e}")
            return None

        logging.error(f"Failed to read from clipboard: {e}")
        return None

