"""Real Windows GUI qualification; only this process's own windows are touched."""
import os
from pathlib import Path
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


@unittest.skipUnless(os.name == 'nt', 'Exécution Windows réelle requise')
class PortableWindowTest(unittest.TestCase):
    def test_worker_completion_closes_window_without_user_action(self):
        from portable_gui import run_window
        completed = threading.Event()
        stopped = threading.Event()
        events = []
        view = {'application': 'ACTIF', 'adoption': 'PÉRIODE EXPIRÉE',
                'active_tests': 0, 'version': '0.9-024'}

        def complete():
            time.sleep(.5)
            completed.set()

        worker = threading.Thread(target=complete)
        worker.start()
        started = time.monotonic()
        try:
            run_window(lambda: view, stopped.set, completed, smoke_seconds=5, lab=True,
                       _event_observer=lambda name, details: events.append(name))
        finally:
            worker.join(2)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(stopped.is_set())
        self.assertIn('tray_removed', events)

    def test_official_icons_minimize_tray_restore_read_only_and_confirmed_exit(self):
        import ctypes
        from ctypes import wintypes as w
        from portable_gui import run_window
        user = ctypes.WinDLL('user32', use_last_error=True)
        signatures = {
            'FindWindowW': ([w.LPCWSTR, w.LPCWSTR], w.HWND),
            'GetClassNameW': ([w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            'GetWindowTextW': ([w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            'PostMessageW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL),
            'SendMessageW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], ctypes.c_ssize_t),
            'IsIconic': ([w.HWND], w.BOOL), 'IsWindowVisible': ([w.HWND], w.BOOL),
            'GetWindowLongPtrW': ([w.HWND, ctypes.c_int], ctypes.c_ssize_t),
            'GetDlgItem': ([w.HWND, ctypes.c_int], w.HWND),
            'GetWindowThreadProcessId': ([w.HWND, ctypes.POINTER(w.DWORD)], w.DWORD),
            'GetClientRect': ([w.HWND, ctypes.POINTER(w.RECT)], w.BOOL),
            'GetWindowRect': ([w.HWND, ctypes.POINTER(w.RECT)], w.BOOL),
            'ScreenToClient': ([w.HWND, ctypes.POINTER(w.POINT)], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            getattr(user, name).argtypes, getattr(user, name).restype = args, result
        ENUM = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        user.EnumChildWindows.argtypes, user.EnumChildWindows.restype = [w.HWND, ENUM, w.LPARAM], w.BOOL
        stopping, completed = threading.Event(), threading.Event()
        errors, observed, events = [], [], []
        view = {'application': 'ACTIF', 'controller': 'CONNECTÉ', 'adoption': 'ADOPTÉ PAR WIFX',
                'sip': 'OK', 'active_tests': 1, 'completed_tests': 4, 'last_test': 'TERMINÉ',
                'version': '0.9-004', 'authorization_remaining_seconds': 7*86400+3*3600,
                'ticket_reference': 'WSUP-1234567', 'error': ''}

        def wait(predicate, message, timeout=5):
            deadline = time.monotonic()+timeout
            while time.monotonic() < deadline:
                value = predicate()
                if value:
                    return value
                time.sleep(.04)
            raise AssertionError(message)

        def stop():
            stopping.set()

        def worker():
            stopping.wait(25)
            time.sleep(.15)
            completed.set()

        def dialog_button(identifier):
            def owned_dialog():
                dialog = user.FindWindowW('#32770', 'Quitter Voice Probe ?')
                if not dialog:
                    return None
                pid = w.DWORD()
                user.GetWindowThreadProcessId(dialog, ctypes.byref(pid))
                return dialog if pid.value == os.getpid() else None
            dialog = wait(owned_dialog, 'Exit confirmation was not displayed')
            button = user.GetDlgItem(dialog, identifier)
            self.assertTrue(button)
            user.PostMessageW(button, 0x00F5, 0, 0)

        def inspect():
            hwnd = None
            try:
                hwnd = wait(lambda: user.FindWindowW('WIFXVoiceProbePortable-'+str(os.getpid()), None), 'Native WIFX window not created')
                wait(lambda: any(e[0] == 'tray_registered' and e[1]['success'] for e in events), 'Native notification icon was not registered')
                self.assertTrue(user.GetWindowLongPtrW(hwnd, -16) & 0x20000, 'Classic minimize box missing')
                for size in (0, 1):
                    self.assertTrue(user.SendMessageW(hwnd, 0x007F, size, 0), 'Official window icon missing')
                time.sleep(.4)
                @ENUM
                def child(window, _):
                    kind, text = ctypes.create_unicode_buffer(100), ctypes.create_unicode_buffer(600)
                    user.GetClassNameW(window, kind, len(kind))
                    user.GetWindowTextW(window, text, len(text))
                    observed.append((window, kind.value, text.value))
                    return True
                user.EnumChildWindows(hwnd, child, 0)
                self.assertEqual({'Static', 'Button'}, {kind for _, kind, _ in observed})
                for expected in ('Quitter', 'Réduire', 'WIFX VOICE PROBE', 'Sonde de diagnostic téléphonique',
                                 'Intervention WSUP-1234567', 'Diagnostic en cours', '4 test(s) terminé(s)', '7 j 3 h'):
                    self.assertTrue(any(text == expected for _, _, text in observed), expected)
                self.assertTrue(any(user.SendMessageW(h, 0x0173, 0, 0) for h, kind, text in observed if kind == 'Static' and not text), 'Official bitmap logo missing')
                client = w.RECT();self.assertTrue(user.GetClientRect(hwnd, ctypes.byref(client)))
                for child_handle, kind, text in observed:
                    if kind == 'Button':
                        rect = w.RECT();self.assertTrue(user.GetWindowRect(child_handle, ctypes.byref(rect)))
                        bottom_right = w.POINT(rect.right, rect.bottom);user.ScreenToClient(hwnd, ctypes.byref(bottom_right))
                        self.assertLessEqual(bottom_right.y, client.bottom, 'Button below window client area')
                        self.assertLessEqual(bottom_right.x, client.right, 'Button outside window client area')
                capture = os.environ.get('WIFX_GUI_CAPTURE')
                if capture:
                    _capture_own_window(hwnd, Path(capture))
                user.PostMessageW(hwnd, 0x0112, 0xF020, 0)
                wait(lambda: user.IsIconic(hwnd), 'Classic taskbar minimize failed')
                self.assertFalse(stopping.is_set(), 'Minimize stopped the worker')
                user.PostMessageW(hwnd, 0x8000+23, 0, (1 << 16)|0x0400)
                wait(lambda: not user.IsIconic(hwnd) and user.IsWindowVisible(hwnd), 'Notification click did not restore window')
                for _ in range(2):
                    user.PostMessageW(hwnd, 0x0111, 1002, 0)
                    wait(lambda: not user.IsWindowVisible(hwnd), 'Reduce did not hide window')
                    self.assertFalse(stopping.is_set(), 'Tray hide stopped the worker')
                    user.PostMessageW(hwnd, 0x8000+23, 0, (1 << 16)|0x0400)
                    wait(lambda: user.IsWindowVisible(hwnd), 'Notification click failed')
                self.assertEqual(1, sum(name == 'background_notification_requested' for name, _ in events))
                user.PostMessageW(hwnd, 0x8000+23, 0, (1 << 16)|0x007B)
                wait(lambda: any(name == 'notification_menu_opened' for name, _ in events), 'Notification menu unavailable')
                user.PostMessageW(hwnd, 0x001F, 0, 0)
                time.sleep(.1)
                user.PostMessageW(hwnd, 0x0111, 1001, 0)
                dialog_button(7)  # NO is the default; diagnostics must continue.
                wait(lambda: any(name == 'quit_confirmation' and not d['accepted'] for name, d in events), 'Cancelled exit not observed')
                self.assertFalse(stopping.is_set(), 'Declining exit stopped diagnostics')
                user.PostMessageW(hwnd, 0x0111, 1001, 0)
                dialog_button(6)
                wait(stopping.is_set, 'Confirmed exit did not stop worker')
            except BaseException as exc:
                errors.append(exc)
            finally:
                view['active_tests'] = 0
                if hwnd:
                    user.PostMessageW(hwnd, 0x001F, 0, 0)
                    dialog = user.FindWindowW('#32770', 'Quitter Voice Probe ?')
                    if dialog:
                        pid = w.DWORD();user.GetWindowThreadProcessId(dialog, ctypes.byref(pid))
                        if pid.value == os.getpid():
                            user.PostMessageW(user.GetDlgItem(dialog, 6), 0x00F5, 0, 0)
                    user.PostMessageW(hwnd, 0x0010, 0, 0)
                else:
                    stop()

        sip = threading.Thread(target=worker)
        inspector = threading.Thread(target=inspect)
        sip.start();inspector.start()
        try:
            run_window(lambda: dict(view), stop, completed, smoke_seconds=22, lab=True,
                       _event_observer=lambda name, details: events.append((name, details)))
        finally:
            stop();sip.join(5);inspector.join(5)
        if errors:
            raise errors[0]
        self.assertTrue(completed.is_set())
        self.assertFalse(sip.is_alive())
        self.assertFalse(inspector.is_alive())
        self.assertTrue(any(name == 'tray_removed' and d['success'] for name, d in events))



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
