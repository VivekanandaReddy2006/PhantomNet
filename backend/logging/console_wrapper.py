"""
console_wrapper.py — Safe Windows console stream wrapper for PhantomNet.

Prevents UnicodeEncodeError: 'charmap' codec can't encode characters on Windows
terminals (CMD / PowerShell) that default to cp1252, cp850, or cp437.

Strategy (applied in order):
  1. Pre-emptively map known Unicode symbols used in PhantomNet logs to ASCII.
  2. Strip emoji / supplemental Unicode characters (U+1F000+) completely.
  3. Encode remaining characters with errors='replace' as a final fallback.
"""

import sys
import re

# ---------------------------------------------------------------------------
# Pre-emptive substitution map: Unicode symbol -> ASCII-safe string.
# Covers every non-ASCII character found in PhantomNet backend logging calls.
# ---------------------------------------------------------------------------
UNICODE_REPLACEMENTS = {
    # Arrows
    '\u2192': '->',   # RIGHT ARROW
    '\u2190': '<-',   # LEFT ARROW
    '\u2194': '<->',  # LEFT RIGHT ARROW
    '\u21a9': '<-',   # LEFTWARDS ARROW WITH HOOK
    '\u21aa': '->',   # RIGHTWARDS ARROW WITH HOOK

    # Dashes / punctuation
    '\u2014': '--',   # EM DASH
    '\u2013': '-',    # EN DASH
    '\u2012': '-',    # FIGURE DASH

    # Box-drawing / borders
    '\u2550': '=',    # BOX DRAWINGS DOUBLE HORIZONTAL
    '\u2500': '-',    # BOX DRAWINGS LIGHT HORIZONTAL
    '\u2502': '|',    # BOX DRAWINGS LIGHT VERTICAL
    '\u2551': '||',   # BOX DRAWINGS DOUBLE VERTICAL

    # Status symbols (commonly used in PhantomNet scripts/services)
    '\u2705': '[OK]',     # WHITE HEAVY CHECK MARK
    '\u2714': '[OK]',     # HEAVY CHECK MARK
    '\u274c': '[FAIL]',   # CROSS MARK
    '\u274e': '[FAIL]',   # CROSS MARK (alt)
    '\u2716': '[X]',      # HEAVY MULTIPLICATION X
    '\u26a0': '[WARN]',   # WARNING SIGN
    '\u2728': '[*]',      # SPARKLES
    '\u23f3': '[TIME]',   # HOURGLASS WITH FLOWING SAND
    '\u1f504': '[SYNC]',  # ANTICLOCKWISE DOWNWARDS AND UPWARDS OPEN CIRCLE ARROWS
    '\u1f680': '[>]',     # ROCKET
    '\u1f4ca': '[CHART]', # BAR CHART
    '\u1f4c4': '[FILE]',  # PAGE FACING UP
    '\u1f3c1': '[DONE]',  # CHEQUERED FLAG
    '\u1f50d': '[FIND]',  # LEFT-POINTING MAGNIFYING GLASS
    '\u1f389': '[OK!]',   # PARTY POPPER
    '\u1f504': '[SYNC]',  # COUNTERCLOCKWISE ARROWS BUTTON

    # Variant selectors (invisible formatting, just strip)
    '\ufe0f': '',     # VARIATION SELECTOR-16
    '\ufe0e': '',     # VARIATION SELECTOR-15

    # Misc
    '\u00b7': '.',    # MIDDLE DOT
    '\u2022': '*',    # BULLET
    '\u25b6': '>',    # BLACK RIGHT-POINTING TRIANGLE
    '\u25c0': '<',    # BLACK LEFT-POINTING TRIANGLE
    '\u00a9': '(c)',  # COPYRIGHT SIGN
    '\u00ae': '(r)',  # REGISTERED SIGN
    '\u2122': '(tm)', # TRADE MARK SIGN
    '\u2139': '(i)',  # INFORMATION SOURCE
}

# Regex matching the emoji / supplemental Unicode ranges not covered above
EMOJI_PATTERN = re.compile(
    "["
    "\U00010000-\U0010ffff"  # Supplemental planes (emoji, etc.)
    "\u2600-\u27BF"          # Misc symbols, dingbats
    "\u2300-\u23FF"          # Misc technical
    "\u2B50"                 # WHITE MEDIUM STAR
    "\u3030"                 # WAVY DASH
    "\u303D"                 # PART ALTERNATION MARK
    "\u3297"                 # CIRCLED IDEOGRAPH CONGRATULATION
    "\u3299"                 # CIRCLED IDEOGRAPH SECRET
    "\u203C"                 # DOUBLE EXCLAMATION MARK
    "\u2049"                 # EXCLAMATION QUESTION MARK
    "]",
    re.UNICODE,
)


def _sanitise(text: str, encoding: str) -> str:
    """
    Returns a version of *text* that is safe to write to a stream using *encoding*.

    Steps:
        1. Replace known Unicode symbols with ASCII equivalents.
        2. Strip remaining emoji / supplemental characters.
        3. Re-encode with errors='replace' for any residual unencodable bytes.
    """
    # Step 1: pre-emptive substitution
    result_chars = []
    for ch in text:
        if ch in UNICODE_REPLACEMENTS:
            result_chars.append(UNICODE_REPLACEMENTS[ch])
        else:
            result_chars.append(ch)
    text = ''.join(result_chars)

    # Step 2: strip remaining emoji / supplemental chars
    text = EMOJI_PATTERN.sub('', text)

    # Step 3: encode/decode with replacement for any leftover unencodable chars
    text = text.encode(encoding, errors='replace').decode(encoding)

    return text


class SafeConsoleStream:
    """
    Wraps sys.stdout / sys.stderr so that Unicode characters that cannot be
    encoded by the Windows console codec are safely sanitised instead of
    raising UnicodeEncodeError.
    """

    def __init__(self, original_stream):
        self._original_stream = original_stream
        self._encoding = getattr(original_stream, 'encoding', None) or 'utf-8'

    # ------------------------------------------------------------------
    def write(self, text: str) -> int:
        if not text:
            return 0
        if not self._original_stream or not hasattr(self._original_stream, 'write'):
            return 0

        # Always pre-substitute known symbols to clean ASCII equivalents
        # (even if the codec can encode the raw glyph, terminal fonts may not render it)
        has_non_ascii = any(ord(c) > 127 for c in text)
        if has_non_ascii:
            text = _sanitise(text, self._encoding)

        try:
            return self._original_stream.write(text)
        except (UnicodeEncodeError, LookupError):
            # Final safety net: replace any remaining unencodable chars
            safe = text.encode(self._encoding, errors='replace').decode(self._encoding)
            try:
                return self._original_stream.write(safe)
            except Exception:
                return 0

    def flush(self):
        if self._original_stream and hasattr(self._original_stream, 'flush'):
            try:
                self._original_stream.flush()
            except Exception:
                pass

    def __getattr__(self, name):
        return getattr(self._original_stream, name)


# ---------------------------------------------------------------------------
# Public helper — call once at startup
# ---------------------------------------------------------------------------

def apply_console_wrapper() -> None:
    """
    Replaces sys.stdout and sys.stderr with SafeConsoleStream wrappers when the
    attached console does not support UTF-8 (i.e. on a typical Windows terminal).

    Safe to call on Linux/macOS — it's a no-op when the stream already uses UTF-8.
    """
    for attr in ('stdout', 'stderr'):
        stream = getattr(sys, attr, None)
        if stream is None:
            continue
        encoding = getattr(stream, 'encoding', '') or ''
        if 'utf' not in encoding.lower():
            setattr(sys, attr, SafeConsoleStream(stream))
