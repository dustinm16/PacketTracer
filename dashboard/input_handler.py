"""Keyboard input handling with fast arrow key support."""

import sys
import select
import termios
import tty
from enum import Enum, auto
from typing import Optional, List
from dataclasses import dataclass

from utils.logger import logger


class Key(Enum):
    """Special key codes."""
    UP = auto()
    DOWN = auto()
    LEFT = auto()
    RIGHT = auto()
    ENTER = auto()
    SPACE = auto()
    ESCAPE = auto()
    TAB = auto()
    BACKSPACE = auto()
    DELETE = auto()
    HOME = auto()
    END = auto()
    PAGE_UP = auto()
    PAGE_DOWN = auto()


@dataclass
class KeyEvent:
    """Represents a key press event."""
    char: Optional[str] = None
    key: Optional[Key] = None

    @property
    def is_special(self) -> bool:
        return self.key is not None

    def __eq__(self, other):
        if isinstance(other, str):
            return self.char == other
        if isinstance(other, Key):
            return self.key == other
        if isinstance(other, KeyEvent):
            return self.char == other.char and self.key == other.key
        return False


class InputHandler:
    """Fast keyboard input handler with arrow key support."""

    # Complete escape sequences mapped to keys
    ESCAPE_SEQUENCES = {
        '\x1b[A': Key.UP,
        '\x1b[B': Key.DOWN,
        '\x1b[C': Key.RIGHT,
        '\x1b[D': Key.LEFT,
        '\x1b[H': Key.HOME,
        '\x1b[F': Key.END,
        '\x1b[5~': Key.PAGE_UP,
        '\x1b[6~': Key.PAGE_DOWN,
        '\x1b[3~': Key.DELETE,
        '\x1bOP': Key.UP,
        '\x1bOQ': Key.DOWN,
        '\x1bOR': Key.RIGHT,
        '\x1bOS': Key.LEFT,
        '\x1b[1~': Key.HOME,
        '\x1b[4~': Key.END,
        # xterm style
        '\x1bOH': Key.HOME,
        '\x1bOF': Key.END,
    }

    def __init__(self):
        self._old_settings = None
        self._active = False
        self._buffer = ""

    def start(self) -> None:
        """Enable cbreak input mode."""
        if self._active:
            logger.debug("Input handler already active")
            return

        logger.info("Starting input handler")

        # Save terminal settings
        self._old_settings = termios.tcgetattr(sys.stdin)
        logger.debug("Saved terminal settings")

        # Set terminal to cbreak mode (not raw!) - this preserves output processing
        # which Rich needs to render properly, while still giving us immediate key input
        tty.setcbreak(sys.stdin.fileno())
        logger.debug("Set terminal to cbreak mode")

        # Note: We use select() for non-blocking checks instead of O_NONBLOCK
        # which can cause BlockingIOError issues with Rich's console
        self._active = True
        logger.info("Input handler started successfully")

    def stop(self) -> None:
        """Restore terminal settings."""
        logger.info("Stopping input handler")

        try:
            if self._old_settings:
                termios.tcsetattr(sys.stdin, termios.TCSAFLUSH, self._old_settings)
                logger.debug("Restored terminal settings")
        except Exception as e:
            logger.error(f"Error restoring terminal settings: {e}")
        finally:
            self._old_settings = None

        self._active = False
        self._buffer = ""
        logger.info("Input handler stopped")

    def _read_available(self, timeout: float = 0) -> str:
        """Read all available characters from stdin using select()."""
        chars = ""
        try:
            while True:
                # Check if there's data available to read
                ready, _, _ = select.select([sys.stdin], [], [], timeout)
                if not ready:
                    break
                c = sys.stdin.read(1)
                if not c:
                    break
                chars += c
                # After first char, don't wait for more
                timeout = 0
        except Exception as e:
            logger.debug(f"Read error (usually harmless): {e}")
        return chars

    def get_key(self, timeout: float = 0) -> Optional[KeyEvent]:
        """Get next key event with minimal latency."""
        # First check buffer from previous reads
        if self._buffer:
            return self._parse_next_key()

        # Wait for input with short timeout
        if timeout > 0:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None

        # Read all available input at once
        self._buffer += self._read_available()

        if not self._buffer:
            return None

        return self._parse_next_key()

    def _parse_next_key(self) -> Optional[KeyEvent]:
        """Parse the next key from the buffer."""
        if not self._buffer:
            return None

        logger.debug(f"Parsing buffer: {repr(self._buffer)}")

        # Check for escape sequences (longest match first)
        for seq, key in sorted(self.ESCAPE_SEQUENCES.items(), key=lambda x: -len(x[0])):
            if self._buffer.startswith(seq):
                self._buffer = self._buffer[len(seq):]
                logger.debug(f"Matched sequence {repr(seq)} -> {key}")
                return KeyEvent(key=key)

        # Check for standalone escape (if buffer is just escape or escape + unknown)
        if self._buffer[0] == '\x1b':
            # Wait for more characters to complete the escape sequence
            # Arrow keys send \x1b[A etc - need to wait for all chars to arrive
            # Use 100ms timeout to ensure we catch single key taps
            self._buffer += self._read_available(timeout=0.1)

            # If still incomplete, wait a bit more
            if len(self._buffer) < 3:
                self._buffer += self._read_available(timeout=0.1)

            # Try matching escape sequences again
            for seq, key in sorted(self.ESCAPE_SEQUENCES.items(), key=lambda x: -len(x[0])):
                if self._buffer.startswith(seq):
                    self._buffer = self._buffer[len(seq):]
                    logger.debug(f"Matched escape sequence {repr(seq)} -> {key}")
                    return KeyEvent(key=key)

            # Check if it could still be a valid prefix (incomplete sequence)
            if len(self._buffer) < 6:  # Max escape sequence length
                is_prefix = any(seq.startswith(self._buffer) for seq in self.ESCAPE_SEQUENCES)
                if is_prefix:
                    # Wait for more input
                    self._buffer += self._read_available(timeout=0.1)
                    # Try one more time
                    for seq, key in sorted(self.ESCAPE_SEQUENCES.items(), key=lambda x: -len(x[0])):
                        if self._buffer.startswith(seq):
                            self._buffer = self._buffer[len(seq):]
                            logger.debug(f"Matched escape sequence (delayed) {repr(seq)} -> {key}")
                            return KeyEvent(key=key)

            # If still just escape or unknown sequence, return escape
            if len(self._buffer) == 1:
                self._buffer = ""
                return KeyEvent(key=Key.ESCAPE)

            # Unknown sequence, skip the escape character
            self._buffer = self._buffer[1:]
            return KeyEvent(key=Key.ESCAPE)

        # Single character
        char = self._buffer[0]
        self._buffer = self._buffer[1:]

        if char == '\r' or char == '\n':
            return KeyEvent(key=Key.ENTER)
        elif char == ' ':
            return KeyEvent(key=Key.SPACE)
        elif char == '\t':
            return KeyEvent(key=Key.TAB)
        elif char == '\x7f' or char == '\x08':
            return KeyEvent(key=Key.BACKSPACE)
        elif char == '\x03':  # Ctrl+C
            raise KeyboardInterrupt
        else:
            return KeyEvent(char=char)

    def get_all_keys(self) -> List[KeyEvent]:
        """Get all pending key events."""
        events = []
        while True:
            event = self.get_key(timeout=0)
            if event is None:
                break
            events.append(event)
        return events

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
