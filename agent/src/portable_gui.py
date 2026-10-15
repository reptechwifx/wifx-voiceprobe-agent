"""Small native Win32 status window. No browser, socket or administrative API."""
import os
import time


def format_authorization_duration(seconds):
    """Human display only; the SIP policy uses its separate bounded lease."""
    if type(seconds) is not int or seconds < 0:
        return 'INDISPONIBLE'
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f'{days} j {hours} h'
    if hours:
        return f'{hours} h {minutes} min'
    if minutes:
        return f'{minutes} min'
    return f'{seconds} s'


def run_window(status_provider, request_stop, worker_done, *, smoke_seconds=None, lab=False):
    """Run on the Windows main thread; callbacks expose no sensitive settings.

    worker_done is a threading.Event. A close request first stops the SIP worker;
    the window stays alive until that worker has released calls and resources.
    smoke_seconds is an explicit qualification hook, never automatic client mode.
    """
    if os.name != 'nt':
        raise RuntimeError('Cette interface nécessite Windows x64.')
    import ctypes
    from ctypes import wintypes as w
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    gdi = ctypes.WinDLL('gdi32', use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WNDCLASS(ctypes.Structure):
        _fields_ = [('style', w.UINT), ('lpfnWndProc', WNDPROC), ('cbClsExtra', ctypes.c_int),
                    ('cbWndExtra', ctypes.c_int), ('hInstance', w.HINSTANCE), ('hIcon', w.HICON),
                    ('hCursor', w.HANDLE), ('hbrBackground', w.HBRUSH), ('lpszMenuName', w.LPCWSTR),
                    ('lpszClassName', w.LPCWSTR)]

    prototypes = {
        'RegisterClassW': ([ctypes.POINTER(WNDCLASS)], w.ATOM),
        'UnregisterClassW': ([w.LPCWSTR, w.HINSTANCE], w.BOOL),
        'CreateWindowExW': ([w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, ctypes.c_void_p], w.HWND),
        'DefWindowProcW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], LRESULT),
        'DestroyWindow': ([w.HWND], w.BOOL),
        'ShowWindow': ([w.HWND, ctypes.c_int], w.BOOL),
        'UpdateWindow': ([w.HWND], w.BOOL),
        'SetWindowTextW': ([w.HWND, w.LPCWSTR], w.BOOL),
        'SendMessageW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], LRESULT),
        'EnableWindow': ([w.HWND, w.BOOL], w.BOOL),
        'GetMessageW': ([ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT], w.BOOL),
        'TranslateMessage': ([ctypes.POINTER(w.MSG)], w.BOOL),
        'DispatchMessageW': ([ctypes.POINTER(w.MSG)], LRESULT),
        'PostQuitMessage': ([ctypes.c_int], None),
        'SetTimer': ([w.HWND, ctypes.c_size_t, w.UINT, ctypes.c_void_p], ctypes.c_size_t),
        'KillTimer': ([w.HWND, ctypes.c_size_t], w.BOOL),
        'LoadCursorW': ([w.HINSTANCE, ctypes.c_void_p], w.HANDLE),
    }
    for name, (args, result) in prototypes.items():
        fn = getattr(user, name)
        fn.argtypes, fn.restype = args, result
    kernel.GetModuleHandleW.argtypes, kernel.GetModuleHandleW.restype = [w.LPCWSTR], w.HMODULE
    gdi.CreateSolidBrush.argtypes, gdi.CreateSolidBrush.restype = [w.COLORREF], w.HBRUSH
    gdi.CreateFontW.argtypes = [ctypes.c_int]*5 + [w.DWORD]*8 + [w.LPCWSTR]
    gdi.CreateFontW.restype = w.HFONT
    gdi.SetTextColor.argtypes, gdi.SetTextColor.restype = [w.HDC, w.COLORREF], w.COLORREF
    gdi.SetBkMode.argtypes, gdi.SetBkMode.restype = [w.HDC, ctypes.c_int], ctypes.c_int
    gdi.DeleteObject.argtypes, gdi.DeleteObject.restype = [w.HGDIOBJ], w.BOOL
    try:
        user.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except AttributeError:
        pass
    instance = kernel.GetModuleHandleW(None)
    background = gdi.CreateSolidBrush(0x00F8F7F5)
    normal_font = gdi.CreateFontW(-17, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, 'Segoe UI')
    title_font = gdi.CreateFontW(-27, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 5, 0, 'Segoe UI')
    class_name = 'WIFXVoiceProbePortable-' + str(os.getpid())
    labels = {}
    values = {}
    colors = {}
    state = {'closing': False, 'button': None, 'started': time.monotonic()}
    rows = [('application', 'Application'), ('controller', 'Connexion WIFX'),
            ('adoption', 'Autorisation'), ('sip', 'Enregistrement SIP'),
            ('tests', 'Tests en cours / réalisés'), ('last_test', 'Dernier test'),
            ('remaining', 'Autorisation restante'), ('version', 'Version Agent')]

    def begin_close(hwnd):
        if state['closing']:
            return
        state['closing'] = True
        user.SetWindowTextW(hwnd, 'WIFX Voice Probe — Arrêt en cours')
        if state['button']:
            user.EnableWindow(state['button'], False)
            user.SetWindowTextW(state['button'], 'Arrêt en cours…')
        request_stop()

    def refresh(hwnd):
        try:
            view = status_provider()
        except Exception:
            view = {'application': 'ERREUR', 'error': 'Diagnostic indisponible. Veuillez contacter WIFX.'}
        data = dict(view)
        data['tests'] = str(data.get('active_tests', 0)) + ' / ' + str(data.get('completed_tests', 0))
        data['remaining'] = format_authorization_duration(data.get('authorization_remaining_seconds'))
        if state['closing']:
            data['application'] = 'ARRÊT EN COURS'
        for key, _ in rows:
            text = str(data.get(key, 'EN ATTENTE'))[:80]
            color = 0x00777777
            if text in ('ACTIF', 'CONNECTÉ', 'ADOPTÉ PAR WIFX', 'OK', 'TERMINÉ'):
                color = 0x00488019
            elif any(word in text for word in ('ERREUR', 'EXPIRÉE', 'RÉVOQUÉE')):
                color = 0x003939BD
            elif any(word in text for word in ('ATTENTE', 'COURS')):
                color = 0x000F7EAD
            colors[values[key]] = color
            user.SetWindowTextW(values[key], text)
        user.SetWindowTextW(labels['error'], str(data.get('error', ''))[:140])
        if smoke_seconds is not None and time.monotonic() - state['started'] >= smoke_seconds:
            begin_close(hwnd)
        if state['closing'] and worker_done.is_set():
            user.DestroyWindow(hwnd)

    @WNDPROC
    def window_proc(hwnd, message, wp, lp):
        if message == 0x0010:  # WM_CLOSE
            begin_close(hwnd)
            return 0
        if message == 0x0111 and (wp & 0xffff) == 1001:  # WM_COMMAND button
            begin_close(hwnd)
            return 0
        if message == 0x0113:  # WM_TIMER
            refresh(hwnd)
            return 0
        if message == 0x0138:  # WM_CTLCOLORSTATIC
            gdi.SetBkMode(wp, 1)
            gdi.SetTextColor(wp, colors.get(lp, 0x00333333))
            return background
        if message == 0x0002:  # WM_DESTROY
            user.KillTimer(hwnd, 1)
            user.PostQuitMessage(0)
            return 0
        return user.DefWindowProcW(hwnd, message, wp, lp)

    cls = WNDCLASS(0, window_proc, 0, 0, instance, None,
                   user.LoadCursorW(None, ctypes.c_void_p(32512)), background, None, class_name)
    registered = False
    hwnd = None
    try:
        if not user.RegisterClassW(ctypes.byref(cls)):
            raise OSError('Création de la fenêtre WIFX impossible.')
        registered = True
        hwnd = user.CreateWindowExW(0, class_name, 'WIFX Voice Probe — Sonde de diagnostic',
                                     0x00CA0000, -2147483648, -2147483648, 570, 535,
                                     None, None, instance, None)
        if not hwnd:
            raise OSError('Création de la fenêtre WIFX impossible.')

        def control(kind, text, x, y, width, height, identifier=0, font=normal_font):
            child = user.CreateWindowExW(0, kind, text, 0x50000000, x, y, width, height,
                                         hwnd, identifier or None, instance, None)
            if not child:
                raise OSError('Création de l’interface WIFX impossible.')
            user.SendMessageW(child, 0x0030, font, 1)
            return child
        control('STATIC', 'WIFX VOICE PROBE', 28, 22, 490, 42, font=title_font)
        control('STATIC', 'Sonde de diagnostic — LAB non signé' if lab else 'Sonde de diagnostic', 30, 65, 510, 28)
        for index, (key, label) in enumerate(rows):
            y = 115 + index*31
            labels[key] = control('STATIC', label, 30, y, 230, 27)
            values[key] = control('STATIC', 'EN ATTENTE', 270, y, 265, 27)
        labels['error'] = control('STATIC', '', 30, 372, 495, 44)
        colors[labels['error']] = 0x003939BD
        state['button'] = control('BUTTON', 'Arrêter et quitter', 165, 432, 230, 40, 1001)
        user.ShowWindow(hwnd, 5)
        user.UpdateWindow(hwnd)
        if not user.SetTimer(hwnd, 1, 250, None):
            raise OSError('Actualisation de l’interface WIFX impossible.')
        refresh(hwnd)
        message = w.MSG()
        while True:
            result = user.GetMessageW(ctypes.byref(message), None, 0, 0)
            if result == -1:
                raise OSError('L’interface Windows a été interrompue.')
            if result == 0:
                break
            user.TranslateMessage(ctypes.byref(message))
            user.DispatchMessageW(ctypes.byref(message))
    finally:
        request_stop()
        if hwnd:
            user.DestroyWindow(hwnd)
        if registered:
            user.UnregisterClassW(class_name, instance)
        for resource in (normal_font, title_font, background):
            if resource:
                gdi.DeleteObject(resource)
