"""Real Windows GUI qualification. No desktop capture or system configuration.

Run with the qualified Windows Python; optional WIFX_GUI_CAPTURE names the PNG
of this process's own window. All status data below is synthetic public data.
"""
import os
from pathlib import Path
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


@unittest.skipUnless(os.name == 'nt', 'Exécution Windows réelle requise')
class PortableWindowTest(unittest.TestCase):
    def test_read_only_native_window_stop_button_and_clean_worker_shutdown(self):
        import ctypes
        from ctypes import wintypes as w
        from portable_gui import run_window
        user = ctypes.WinDLL('user32', use_last_error=True)
        user.FindWindowW.argtypes, user.FindWindowW.restype = [w.LPCWSTR, w.LPCWSTR], w.HWND
        user.GetClassNameW.argtypes, user.GetClassNameW.restype = [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int
        user.GetWindowTextW.argtypes, user.GetWindowTextW.restype = [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int
        user.PostMessageW.argtypes, user.PostMessageW.restype = [w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL
        ENUM = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        user.EnumChildWindows.argtypes, user.EnumChildWindows.restype = [w.HWND, ENUM, w.LPARAM], w.BOOL
        stopping, completed = threading.Event(), threading.Event()
        errors = []
        observed = []
        callback_called = []
        view = {'application': 'ACTIF', 'controller': 'CONNECTÉ', 'adoption': 'ADOPTÉ PAR WIFX',
                'sip': 'OK', 'active_tests': 1, 'completed_tests': 4, 'last_test': 'TERMINÉ',
                'version': '0.9-004', 'remaining_seconds': 45,
                'authorization_remaining_seconds': 7*86400+3*3600, 'error': ''}

        def stop():
            callback_called.append(True)
            stopping.set()

        def worker():
            stopping.wait(20)
            # Emulates draining/releasing the SIP worker before the GUI exits.
            time.sleep(.1)
            completed.set()

        def inspect():
            hwnd = None
            try:
                for _ in range(100):
                    hwnd = user.FindWindowW('WIFXVoiceProbePortable-' + str(os.getpid()), None)
                    if hwnd:
                        break
                    time.sleep(.05)
                if not hwnd:
                    raise AssertionError('Native WIFX window was not created')
                time.sleep(.75)
                @ENUM
                def child(window, _):
                    kind, text = ctypes.create_unicode_buffer(100), ctypes.create_unicode_buffer(200)
                    user.GetClassNameW(window, kind, len(kind))
                    user.GetWindowTextW(window, text, len(text))
                    observed.append((kind.value, text.value))
                    return True
                user.EnumChildWindows(hwnd, child, 0)
                self.assertEqual({'Static', 'Button'}, {x[0] for x in observed})
                self.assertIn(('Button', 'Arrêter et quitter'), observed)
                for expected in ('WIFX VOICE PROBE', 'Sonde de diagnostic — LAB non signé', 'ACTIF', 'CONNECTÉ', 'ADOPTÉ PAR WIFX', 'OK', '0.9-004', '7 j 3 h'):
                    self.assertTrue(any(text == expected for _, text in observed), expected)
                capture = os.environ.get('WIFX_GUI_CAPTURE')
                if capture:
                    _capture_own_window(hwnd, Path(capture))
            except BaseException as exc:
                errors.append(exc)
            finally:
                if hwnd:
                    # Exercise the real button's WM_COMMAND rather than a timer.
                    user.PostMessageW(hwnd, 0x0111, 1001, 0)
                else:
                    stop()
        sip = threading.Thread(target=worker)
        inspector = threading.Thread(target=inspect)
        sip.start(); inspector.start()
        try:
            run_window(lambda: dict(view), stop, completed, smoke_seconds=15, lab=True)
        finally:
            stop(); sip.join(5); inspector.join(5)
        if errors:
            raise errors[0]
        self.assertTrue(callback_called)
        self.assertTrue(completed.is_set())
        self.assertFalse(sip.is_alive())
        self.assertFalse(inspector.is_alive())


def _capture_own_window(hwnd, destination):
    """PrintWindow only our window, encode PNG using stdlib (no desktop pixels)."""
    import ctypes
    from ctypes import wintypes as w
    import struct
    import zlib
    user, gdi = ctypes.WinDLL('user32'), ctypes.WinDLL('gdi32')
    user.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
    user.GetWindowDC.argtypes, user.GetWindowDC.restype = [w.HWND], w.HDC
    user.ReleaseDC.argtypes = [w.HWND, w.HDC]
    user.PrintWindow.argtypes, user.PrintWindow.restype = [w.HWND, w.HDC, w.UINT], w.BOOL
    gdi.CreateCompatibleDC.argtypes, gdi.CreateCompatibleDC.restype = [w.HDC], w.HDC
    gdi.CreateCompatibleBitmap.argtypes, gdi.CreateCompatibleBitmap.restype = [w.HDC, ctypes.c_int, ctypes.c_int], w.HBITMAP
    gdi.SelectObject.argtypes, gdi.SelectObject.restype = [w.HDC, w.HGDIOBJ], w.HGDIOBJ
    gdi.DeleteObject.argtypes = [w.HGDIOBJ]
    gdi.DeleteDC.argtypes = [w.HDC]
    gdi.GetDIBits.argtypes = [w.HDC, w.HBITMAP, w.UINT, w.UINT, ctypes.c_void_p, ctypes.c_void_p, w.UINT]
    rect = w.RECT()
    if not user.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise OSError('Window rectangle unavailable')
    width, height = rect.right-rect.left, rect.bottom-rect.top
    dc = user.GetWindowDC(hwnd)
    memory = gdi.CreateCompatibleDC(dc)
    bitmap = gdi.CreateCompatibleBitmap(dc, width, height)
    previous = gdi.SelectObject(memory, bitmap)
    try:
        if not user.PrintWindow(hwnd, memory, 2):
            raise OSError('Window-only capture unavailable')
        gdi.SelectObject(memory, previous)
        info = ctypes.create_string_buffer(struct.pack('<IiiHHIIiiII', 40, width, -height, 1, 32, 0, width*height*4, 0, 0, 0, 0))
        pixels = ctypes.create_string_buffer(width*height*4)
        if gdi.GetDIBits(memory, bitmap, 0, height, pixels, info, 0) != height:
            raise OSError('Window pixels unavailable')
        raw = pixels.raw
        rows = []
        for y in range(height):
            row = bytearray(b'\0')
            for x in range(width):
                offset = (y*width+x)*4
                row.extend((raw[offset+2], raw[offset+1], raw[offset], 255))
            rows.append(bytes(row))
        def chunk(kind, data):
            return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind+data)&0xffffffff)
        png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', width, height, 8, 6, 0, 0, 0))
        png += chunk(b'IDAT', zlib.compress(b''.join(rows))) + chunk(b'IEND', b'')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(png)
    finally:
        gdi.SelectObject(memory, previous)
        gdi.DeleteObject(bitmap); gdi.DeleteDC(memory); user.ReleaseDC(hwnd, dc)


if __name__ == '__main__':
    unittest.main()
