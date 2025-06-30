import logging
from typing import Callable, Iterable, Tuple, List, Set

KeyId = Tuple[str, int | object]

class KeyComboDetector:
    """Detect configured key combinations and call their actions once per press."""

    def __init__(self, combos: List[Tuple[Iterable[KeyId], Callable[[], None]]]):
        self.combo_actions = [(frozenset(c), a) for c, a in combos]
        self.pressed: Set[KeyId] = set()
        self.active_combo: Set[KeyId] | None = None

    def press(self, key: KeyId) -> None:
        self.pressed.add(key)
        self._check()

    def release(self, key: KeyId) -> None:
        self.pressed.discard(key)
        if self.active_combo and not self.active_combo.issubset(self.pressed):
            self.active_combo = None

    def _check(self) -> None:
        if self.active_combo:
            return
        for combo, action in self.combo_actions:
            if combo.issubset(self.pressed):
                logging.debug("Combo detected: %s", combo)
                self.active_combo = set(combo)
                action()
                break

def key_to_id(key: object) -> KeyId:
    vk = getattr(key, "vk", None)
    if vk is not None:
        return ("vk", vk)
    return ("key", key)
