"""Small Windows SAME_PROCESS protected mutable secret buffers.

Protects owned storage while idle and tries VirtualLock (without adjusting OS
quotas). Borrowing necessarily creates Python/HTTP/PJSIP copies; those copies,
debuggers, crash dumps and administrators remain outside this guarantee. This
is not encrypted transport and does not make a hostile host trustworthy.
"""
import contextlib
import ctypes
import os
import threading

from portable_runtime import PortableError


class ProtectedSecret:
    MAX_BYTES = 4096

    def __init__(self, value):
        if not isinstance(value, (bytes, bytearray)) or not 1 <= len(value) <= self.MAX_BYTES:
            raise PortableError('Taille de secret temporaire invalide.')
        if os.name != 'nt':
            raise PortableError('La protection mémoire Windows nécessite Windows.')
        from ctypes import wintypes as w
        self._lock = threading.RLock(); self._closed = False; self._encrypted = False
        self._length = len(value); self._capacity = (self._length+15)//16*16
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self._crypt = ctypes.WinDLL('crypt32', use_last_error=True)
        self._kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, w.DWORD, w.DWORD]
        self._kernel.VirtualAlloc.restype = ctypes.c_void_p
        self._kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, w.DWORD]; self._kernel.VirtualFree.restype = w.BOOL
        for name in ('VirtualLock', 'VirtualUnlock'):
            fn = getattr(self._kernel, name); fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]; fn.restype = w.BOOL
        for name in ('CryptProtectMemory', 'CryptUnprotectMemory'):
            fn = getattr(self._crypt, name); fn.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD]; fn.restype = w.BOOL
        self._pointer = self._kernel.VirtualAlloc(None, self._capacity, 0x3000, 0x04)
        if not self._pointer:
            raise PortableError('Mémoire protégée Windows indisponible.')
        self.locked = bool(self._kernel.VirtualLock(self._pointer, self._capacity))
        try:
            source = (ctypes.c_char * len(value)).from_buffer(value) if isinstance(value, bytearray) else value
            ctypes.memmove(self._pointer, source, self._length)
            self._protect()
        except BaseException:
            self.close(); raise

    def _protect(self):
        if not self._crypt.CryptProtectMemory(self._pointer, self._capacity, 0):
            raise PortableError('Protection du secret temporaire impossible.')
        self._encrypted = True

    @contextlib.contextmanager
    def borrow(self):
        """Yield an owned mutable copy; zero that copy and reprotect on exit.

        Callers must not retain str/bytes conversions outside this scope. Native
        consumers may make their own copies, which this class cannot erase.
        """
        with self._lock:
            if self._closed:
                raise PortableError('Le secret temporaire est fermé.')
            if not self._crypt.CryptUnprotectMemory(self._pointer, self._capacity, 0):
                raise PortableError('Lecture du secret temporaire refusée.')
            self._encrypted = False
            temporary = bytearray(self._length)
            ctypes.memmove((ctypes.c_char * self._length).from_buffer(temporary), self._pointer, self._length)
            try:
                self._protect()
            except BaseException:
                temporary[:] = b'\0' * len(temporary)
                self.close()
                raise
            try:
                yield temporary
            finally:
                temporary[:] = b'\0' * len(temporary)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._pointer:
                ctypes.memset(self._pointer, 0, self._capacity)
                if self.locked:
                    self._kernel.VirtualUnlock(self._pointer, self._capacity)
                self._kernel.VirtualFree(self._pointer, 0, 0x8000)
                self._pointer = None

    def __repr__(self):
        return '<ProtectedSecret closed>' if self._closed else '<ProtectedSecret protected>'


class ProtectedSessionConfig(dict):
    """Keep the owned bearer slot encrypted while idle; never persist it.

    Reads create transient Python strings required by requests/websockets. Those
    libraries can retain copies for the lifetime of an active request/socket.
    dict serialization intentionally sees an empty token, not the secret.
    """
    def __init__(self, values):
        self._secret_lock = threading.RLock()
        self._bearer = None
        super().__init__()
        self.update(values)

    def __setitem__(self, key, value):
        if key != 'token':
            return super().__setitem__(key, value)
        with self._secret_lock:
            replacement = ProtectedSecret(value.encode('ascii')) if value else None
            if self._bearer is not None:
                self._bearer.close()
            self._bearer = replacement
            super().__setitem__('token', '')

    def __getitem__(self, key):
        if key != 'token':
            return super().__getitem__(key)
        with self._secret_lock:
            if 'token' not in self:
                raise KeyError(key)
            if self._bearer is None:
                return ''
            with self._bearer.borrow() as value:
                return value.decode('ascii')

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def update(self, values=(), **kwargs):
        for key, value in dict(values, **kwargs).items():
            self[key] = value

    def pop(self, key, *default):
        if key != 'token':
            return super().pop(key, *default)
        with self._secret_lock:
            if key not in self:
                if default: return default[0]
                raise KeyError(key)
            value = self[key]
            self.__delitem__(key)
            return value

    def __delitem__(self, key):
        if key != 'token':
            return super().__delitem__(key)
        with self._secret_lock:
            if self._bearer is not None:
                self._bearer.close(); self._bearer = None
            super().__delitem__(key)

    def clear(self):
        with self._secret_lock:
            if self._bearer is not None:
                self._bearer.close(); self._bearer = None
            super().clear()


from journal import EventJournal


class ProtectedJournal(EventJournal):
    """Protect owned redaction patterns, retaining only already-redacted events.

    EventJournal needs short-lived str patterns during redact(). PJSIP/requests
    copies remain outside this storage guarantee; no plaintext is logged here.
    """
    def __init__(self, previous):
        self._patterns_lock = threading.RLock()
        self._patterns = []
        super().__init__(secrets=previous.secrets)
        self.events = previous.events
        self.lock = previous.lock
        previous.secrets = ()

    @property
    def secrets(self):
        with self._patterns_lock:
            result = []
            for value in self._patterns:
                with value.borrow() as raw:
                    result.append(raw.decode('utf-8'))
            return tuple(result)

    @secrets.setter
    def secrets(self, values):
        with self._patterns_lock:
            replacement = []
            try:
                for value in values:
                    if value:
                        replacement.append(ProtectedSecret(str(value).encode('utf-8')))
            except BaseException:
                for value in replacement:
                    value.close()
                raise
            for value in self._patterns:
                value.close()
            self._patterns = replacement
