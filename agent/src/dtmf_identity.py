"""Version 1 of the short, call-local DTMF identification frame.

PJSUA2's onDtmfEvent callback supplies RTP event updates. The caller
deduplicates them by event timestamp before feeding this decoder.
SIP INFO uses onDtmfDigit separately.
"""

import re
import time

TOKEN_DIGITS = 10
FRAME_LENGTH = 15
IDENTIFICATION_SECONDS = 10.0
DTMF_DURATION_MS = 160
FRAME_PATTERN = re.compile(r"\*[12][0-9]{12}#\Z")


def checksum(body):
    remainder = 0
    for digit in body:
        remainder = (remainder * 10 + int(digit)) % 97
    return f"{remainder:02d}"


def frame(kind, token):
    if kind not in ("1", "2") or not re.fullmatch(r"[0-9]{10}", token):
        raise ValueError("Invalid DTMF frame")
    body = kind + token
    return "*" + body + checksum(body) + "#"


def decode(value):
    if not isinstance(value, str) or not FRAME_PATTERN.fullmatch(value):
        return None
    body = value[1:12]
    return (body[0], body[1:]) if value[12:14] == checksum(body) else None


class FrameReceiver:
    def __init__(self, clock=time.monotonic, expected_kind=None):
        self.clock = clock
        self.expected_kind = expected_kind
        self.started = None
        self.buffer = ""
        self.last_digit_at = None
        self.result = None
        self.invalid = 0
        self.digits_seen = 0

    def start(self):
        self.started = self.clock()

    def feed(self, digit):
        now = self.clock()
        if self.started is None or now - self.started > IDENTIFICATION_SECONDS or self.result:
            return None
        if not isinstance(digit, str) or len(digit) != 1:
            return None
        self.digits_seen += 1
        if self.last_digit_at is not None and now - self.last_digit_at > 1.0:
            self.buffer = ""
        self.last_digit_at = now
        if digit == "*":
            self.buffer = "*"
        elif self.buffer:
            self.buffer += digit
        if len(self.buffer) > FRAME_LENGTH:
            self.invalid += 1
            self.buffer = ""
        elif digit == "#" and self.buffer:
            candidate = decode(self.buffer)
            self.buffer = ""
            if candidate and (self.expected_kind is None or candidate[0] == self.expected_kind):
                self.result = candidate
                return candidate
            self.invalid += 1
        return None
