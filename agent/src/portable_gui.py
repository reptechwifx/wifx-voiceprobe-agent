"""Native, read-only WIFX window and notification icon; no administrative API."""
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import math
from pathlib import Path
import re
import sys
import time


def format_authorization_duration(seconds):
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


def ticket_title(view):
    reference = view.get('ticket_reference', view.get('support_reference', ''))
    return 'Intervention ' + reference if isinstance(reference, str) and re.fullmatch(r'WSUP-[0-9]{1,7}', reference) else 'Intervention WIFX'


def client_notice(view, *, closing=False):
    if closing:
        return ('ARRÊT EN COURS', 'La sonde libère les appels et les connexions. La fenêtre se fermera automatiquement.', 'neutral')
    state = str(view.get('adoption', ''))
    if 'EXPIRÉ' in state:
        return ('PÉRIODE DE DIAGNOSTIC EXPIRÉE',
                "La période d’utilisation autorisée par WIFX est maintenant terminée. Cette application n’effectuera plus de tests.\n\nVous pouvez fermer l’application et supprimer le fichier si vous n’en avez plus besoin. Pour une nouvelle intervention, contactez votre technicien WIFX.", 'bad')
    if 'RÉVOQU' in state:
        return ('AUTORISATION RÉVOQUÉE', "Cette sonde n’est plus autorisée à effectuer des tests. Vous pouvez fermer l’application. Pour toute question, contactez votre technicien WIFX.", 'bad')
    if int(view.get('active_tests', 0)) > 0:
        return ('DIAGNOSTIC EN COURS',
                'Votre technicien WIFX effectue des contrôles sur votre connexion téléphonique. Veuillez laisser cette fenêtre ouverte pendant toute la durée de l’intervention.\n\nVous pouvez continuer à utiliser votre ordinateur normalement.', 'info')
    if view.get('controller') == 'CONNECTÉ' and 'ADOPTÉ' in state:
        return ('SONDE PRÊTE', 'Votre sonde est connectée à WIFX. Les diagnostics démarreront automatiquement lorsque votre technicien les aura programmés.\n\nRéduire la fenêtre laisse les diagnostics actifs.', 'info')
    return ('PRÉPARATION DE LA SONDE', 'Votre sonde attend sa connexion ou son autorisation WIFX. Aucune configuration technique n’est nécessaire.\n\nVeuillez laisser cette fenêtre ouverte.', 'neutral')


def tray_tooltip(view):
    connected = 'Connecté à WIFX' if view.get('controller') == 'CONNECTÉ' else 'Connexion WIFX en attente'
    if 'EXPIRÉ' in str(view.get('adoption', '')):
        activity = 'Autorisation expirée'
    elif 'RÉVOQU' in str(view.get('adoption', '')):
        activity = 'Autorisation révoquée'
    else:
        activity = 'Diagnostic actif' if int(view.get('active_tests', 0)) > 0 else 'En attente de tests'
    return ('WIFX Voice Probe\n' + connected + '\n' + activity)[:127]


def badge_tone(text):
    if any(word in text.upper() for word in ('ERREUR', 'EXPIRÉ', 'RÉVOQU', 'AUCUN MÉDIA')):
        return 'bad'
    if text in ('ACTIF', 'CONNECTÉ', 'ADOPTÉ PAR WIFX', 'OK', 'TERMINÉ'):
        return 'good'
    if any(word in text.upper() for word in ('ATTENTE', 'COURS', 'PRÉVU')):
        return 'warning'
    return 'neutral'


def metric_text(value, unit):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        return '—'
    return f'{value:.2f}'.replace('.', ',')+' '+unit


def run_window(status_provider, request_stop, worker_done, *, smoke_seconds=None, lab=False, _event_observer=None):
    """All callbacks execute on the GUI thread; reducing never calls request_stop.

    Only explicit exit requests stop SIP. A live call requires confirmation.
    The optional observer reports GUI events to local qualification tests only.
    """
    if os.name != 'nt':
        raise RuntimeError('Cette interface nécessite Windows x64.')
    if smoke_seconds is not None and not lab:
        raise ValueError('Le minuteur de qualification est réservé au LAB.')
    import ctypes
    from ctypes import wintypes as w
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    gdi = ctypes.WinDLL('gdi32', use_last_error=True)
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    result_type = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(result_type, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WNDCLASS(ctypes.Structure):
        _fields_ = [('style', w.UINT), ('lpfnWndProc', WNDPROC), ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
                    ('hInstance', w.HINSTANCE), ('hIcon', w.HICON), ('hCursor', w.HANDLE), ('hbrBackground', w.HBRUSH),
                    ('lpszMenuName', w.LPCWSTR), ('lpszClassName', w.LPCWSTR)]

    class GUID(ctypes.Structure):
        _fields_ = [('Data1', w.DWORD), ('Data2', w.WORD), ('Data3', w.WORD), ('Data4', w.BYTE*8)]

    class NOTIFYICONDATA(ctypes.Structure):
        _fields_ = [('cbSize', w.DWORD), ('hWnd', w.HWND), ('uID', w.UINT), ('uFlags', w.UINT),
                    ('uCallbackMessage', w.UINT), ('hIcon', w.HICON), ('szTip', w.WCHAR*128),
                    ('dwState', w.DWORD), ('dwStateMask', w.DWORD), ('szInfo', w.WCHAR*256),
                    ('uVersion', w.UINT), ('szInfoTitle', w.WCHAR*64), ('dwInfoFlags', w.DWORD),
                    ('guidItem', GUID), ('hBalloonIcon', w.HICON)]

    class PAINTSTRUCT(ctypes.Structure):
        _fields_ = [('hdc', w.HDC), ('fErase', w.BOOL), ('rcPaint', w.RECT), ('fRestore', w.BOOL),
                    ('fIncUpdate', w.BOOL), ('rgbReserved', w.BYTE*32)]

    prototypes = {
        'RegisterClassW': ([ctypes.POINTER(WNDCLASS)], w.ATOM), 'UnregisterClassW': ([w.LPCWSTR, w.HINSTANCE], w.BOOL),
        'CreateWindowExW': ([w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, ctypes.c_void_p], w.HWND),
        'DefWindowProcW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], result_type), 'DestroyWindow': ([w.HWND], w.BOOL),
        'ShowWindow': ([w.HWND, ctypes.c_int], w.BOOL), 'UpdateWindow': ([w.HWND], w.BOOL),
        'SetWindowTextW': ([w.HWND, w.LPCWSTR], w.BOOL), 'SendMessageW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], result_type),
        'EnableWindow': ([w.HWND, w.BOOL], w.BOOL), 'GetMessageW': ([ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT], w.BOOL),
        'TranslateMessage': ([ctypes.POINTER(w.MSG)], w.BOOL), 'DispatchMessageW': ([ctypes.POINTER(w.MSG)], result_type),
        'PostQuitMessage': ([ctypes.c_int], None), 'SetTimer': ([w.HWND, ctypes.c_size_t, w.UINT, ctypes.c_void_p], ctypes.c_size_t),
        'KillTimer': ([w.HWND, ctypes.c_size_t], w.BOOL), 'LoadCursorW': ([w.HINSTANCE, ctypes.c_void_p], w.HANDLE),
        'LoadImageW': ([w.HINSTANCE, w.LPCWSTR, w.UINT, ctypes.c_int, ctypes.c_int, w.UINT], w.HANDLE),
        'DestroyIcon': ([w.HICON], w.BOOL), 'SetForegroundWindow': ([w.HWND], w.BOOL),
        'MessageBoxW': ([w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT], ctypes.c_int),
        'CreatePopupMenu': ([], w.HMENU), 'AppendMenuW': ([w.HMENU, w.UINT, ctypes.c_size_t, w.LPCWSTR], w.BOOL),
        'DestroyMenu': ([w.HMENU], w.BOOL), 'TrackPopupMenu': ([w.HMENU, w.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, ctypes.c_void_p], w.UINT),
        'GetCursorPos': ([ctypes.POINTER(w.POINT)], w.BOOL), 'PostMessageW': ([w.HWND, w.UINT, w.WPARAM, w.LPARAM], w.BOOL),
        'RegisterWindowMessageW': ([w.LPCWSTR], w.UINT), 'InvalidateRect': ([w.HWND, ctypes.c_void_p, w.BOOL], w.BOOL),
        'BeginPaint': ([w.HWND, ctypes.POINTER(PAINTSTRUCT)], w.HDC), 'EndPaint': ([w.HWND, ctypes.POINTER(PAINTSTRUCT)], w.BOOL),
        'FillRect': ([w.HDC, ctypes.POINTER(w.RECT), w.HBRUSH], ctypes.c_int),
        'SystemParametersInfoW': ([w.UINT, w.UINT, ctypes.c_void_p, w.UINT], w.BOOL),
    }
    for name, (args, result) in prototypes.items():
        getattr(user, name).argtypes, getattr(user, name).restype = args, result
    kernel.GetModuleHandleW.argtypes, kernel.GetModuleHandleW.restype = [w.LPCWSTR], w.HMODULE
    gdi.CreateSolidBrush.argtypes, gdi.CreateSolidBrush.restype = [w.COLORREF], w.HBRUSH
    gdi.CreateFontW.argtypes, gdi.CreateFontW.restype = [ctypes.c_int]*5 + [w.DWORD]*8 + [w.LPCWSTR], w.HFONT
    gdi.SetTextColor.argtypes, gdi.SetTextColor.restype = [w.HDC, w.COLORREF], w.COLORREF
    gdi.SetBkMode.argtypes, gdi.SetBkMode.restype = [w.HDC, ctypes.c_int], ctypes.c_int
    gdi.DeleteObject.argtypes, gdi.DeleteObject.restype = [w.HGDIOBJ], w.BOOL
    gdi.SelectObject.argtypes, gdi.SelectObject.restype = [w.HDC, w.HGDIOBJ], w.HGDIOBJ
    gdi.GetStockObject.argtypes, gdi.GetStockObject.restype = [ctypes.c_int], w.HGDIOBJ
    gdi.RoundRect.argtypes, gdi.RoundRect.restype = [w.HDC]+[ctypes.c_int]*6, w.BOOL
    shell.Shell_NotifyIconW.argtypes, shell.Shell_NotifyIconW.restype = [w.DWORD, ctypes.POINTER(NOTIFYICONDATA)], w.BOOL
    try:
        user.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        user.GetDpiForSystem.restype = w.UINT
        scale = user.GetDpiForSystem()/96
    except AttributeError:
        scale = 1
    work_area = w.RECT()
    has_work_area = bool(user.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0))
    if has_work_area:
        scale = min(scale, (work_area.bottom-work_area.top-80)/810, (work_area.right-work_area.left-48)/620)
    px = lambda value: round(value*scale)
    # The logical layout is a client rectangle: calculate the outer frame explicitly.
    frame = w.RECT(0, 0, px(620), px(810))
    user.AdjustWindowRectEx.argtypes = [ctypes.POINTER(w.RECT), w.DWORD, w.BOOL, w.DWORD]
    user.AdjustWindowRectEx(ctypes.byref(frame), 0x00CA0000, False, 0)
    outer_width, outer_height = frame.right-frame.left, frame.bottom-frame.top
    left = work_area.left+(work_area.right-work_area.left-outer_width)//2 if has_work_area else -2147483648
    top = work_area.top+(work_area.bottom-work_area.top-outer_height)//2 if has_work_area else -2147483648
    def color(value):
        r, g, b = bytes.fromhex(value.lstrip('#'))
        return r | g << 8 | b << 16
    backgrounds = {'page': '#F4F7FB', 'white': '#FFFFFF', 'good': '#E7F5EE', 'warning': '#FFF3D5', 'bad': '#FDE9E9', 'neutral': '#EAF0F5', 'info': '#EAF2FF'}
    foregrounds = {'good': '#19754A', 'warning': '#956400', 'bad': '#AF2630', 'neutral': '#576775', 'info': '#1556A3', 'normal': '#223F5B'}
    brushes = {name: gdi.CreateSolidBrush(color(value)) for name, value in backgrounds.items()}
    brushes['brand'] = gdi.CreateSolidBrush(color('#1556A3'))
    def font(size, weight=400):
        return gdi.CreateFontW(-px(size), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, 'Segoe UI')
    fonts = [font(15), font(21, 700), font(13), font(15, 600), font(13, 600)]
    normal_font, title_font, small_font, bold_font, small_bold = fonts
    instance = kernel.GetModuleHandleW(None)
    assets = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]/'windows'))/'assets'
    if not (assets/'wifx.ico').is_file() or not (assets/'wifx-logo.bmp').is_file():
        raise RuntimeError('Ressources graphiques WIFX embarquées indisponibles.')
    large_icon = user.LoadImageW(None, str(assets/'wifx.ico'), 1, px(32), px(32), 0x10)
    small_icon = user.LoadImageW(None, str(assets/'wifx.ico'), 1, px(16), px(16), 0x10)
    bitmap = user.LoadImageW(None, str(assets/'wifx-logo.bmp'), 0, px(120), px(49), 0x2010)
    if not all((large_icon, small_icon, bitmap)):
        raise RuntimeError('Chargement des ressources WIFX impossible.')
    class_name = 'WIFXVoiceProbePortable-' + str(os.getpid())
    rows = [('application', 'Application'), ('controller', 'Connexion WIFX'), ('adoption', 'Autorisation'),
            ('sip', 'Enregistrement SIP'), ('diagnostic', 'Diagnostic'), ('count', 'Tests réalisés'),
            ('last_test', 'Dernier résultat'), ('remaining', 'Temps restant')]
    values, controls, styles = {}, {}, {}
    state = {'closing': False, 'hidden': False, 'tray': False, 'notified': False, 'started': time.monotonic(), 'last': {}, 'notice_tone': 'neutral', 'tip': None}
    callback_message, taskbar_created = 0x8000+23, user.RegisterWindowMessageW('TaskbarCreated')

    def event(name, **details):
        if _event_observer:
            _event_observer(name, details)

    def tray_data(hwnd):
        data = NOTIFYICONDATA()
        data.cbSize, data.hWnd, data.uID = ctypes.sizeof(data), hwnd, 1
        return data

    def add_tray(hwnd):
        data = tray_data(hwnd)
        data.uFlags, data.uCallbackMessage, data.hIcon = 1|2|4|0x80, callback_message, small_icon
        data.szTip = tray_tooltip(state['last'])
        ok = bool(shell.Shell_NotifyIconW(0, ctypes.byref(data)))
        if ok:
            data.uVersion = 4
            if not shell.Shell_NotifyIconW(4, ctypes.byref(data)):
                shell.Shell_NotifyIconW(2, ctypes.byref(data))
                ok = False
        state['tray'] = ok
        event('tray_registered', success=ok)
        return ok

    def remove_tray(hwnd):
        if state['tray']:
            data = tray_data(hwnd)
            ok = bool(shell.Shell_NotifyIconW(2, ctypes.byref(data)))
            state['tray'] = False
            event('tray_removed', success=ok)

    def restore(hwnd):
        user.ShowWindow(hwnd, 9)
        user.SetForegroundWindow(hwnd)
        state['hidden'] = False
        event('restored')

    def minimize_to_tray(hwnd):
        if state['closing']:
            return
        if not state['tray'] and not add_tray(hwnd):
            user.SetWindowTextW(controls['error'], 'Zone de notification indisponible. Utilisez le bouton Windows « _ ».')
            return
        user.ShowWindow(hwnd, 0)
        state['hidden'] = True
        event('minimized_to_tray')
        if not state['notified']:
            data = tray_data(hwnd)
            data.uFlags, data.dwInfoFlags = 0x10, 1|0x80
            data.szInfoTitle = 'WIFX Voice Probe'
            data.szInfo = 'WIFX Voice Probe continue ses diagnostics en arrière-plan. Cliquez sur l’icône WIFX pour afficher la fenêtre.'
            if shell.Shell_NotifyIconW(1, ctypes.byref(data)):
                state['notified'] = True
                event('background_notification_requested')

    def begin_close(hwnd, *, confirm=True):
        if state['closing']:
            return
        try:
            active = int(status_provider().get('active_tests', 0)) > 0
        except Exception:
            active = int(state['last'].get('active_tests', 0)) > 0
        if active and confirm:
            restore(hwnd)
            answer = user.MessageBoxW(hwnd, 'Un diagnostic téléphonique est en cours.\nQuitter interrompra les appels de test en cours.\n\nVoulez-vous arrêter la sonde et quitter ?', 'Quitter Voice Probe ?', 4|0x20|0x100)
            event('quit_confirmation', accepted=answer == 6)
            if answer != 6:
                return
        state['closing'] = True
        user.SetWindowTextW(hwnd, 'WIFX Voice Probe — Arrêt en cours')
        for key in ('quit', 'minimize'):
            if controls.get(key):
                user.EnableWindow(controls[key], False)
        request_stop()
        event('stop_requested')

    def context_menu(hwnd):
        menu = user.CreatePopupMenu()
        if not menu:
            return
        try:
            user.AppendMenuW(menu, 0, 1003, 'Afficher Voice Probe')
            user.AppendMenuW(menu, 1, 1004, 'Statut actuel : ' + ' · '.join(tray_tooltip(state['last']).split('\n')[1:]))
            user.AppendMenuW(menu, 0x800, 0, None)
            user.AppendMenuW(menu, 0, 1001, 'Quitter')
            point = w.POINT()
            user.GetCursorPos(ctypes.byref(point))
            user.SetForegroundWindow(hwnd)
            event('notification_menu_opened', entries=['Afficher Voice Probe', 'Statut actuel', 'Quitter'])
            selected = user.TrackPopupMenu(menu, 0x100|0x80|2, point.x, point.y, 0, hwnd, None)
            if selected == 1003:
                restore(hwnd)
            elif selected == 1001:
                begin_close(hwnd)
            user.PostMessageW(hwnd, 0, 0, 0)
        finally:
            user.DestroyMenu(menu)

    def refresh(hwnd):
        try:
            view = dict(status_provider())
        except Exception:
            view = {'application': 'ERREUR', 'error': 'Diagnostic indisponible. Veuillez contacter WIFX.'}
        state['last'] = view
        data = dict(view)
        active = max(0, int(view.get('active_tests', 0)))
        data['diagnostic'] = 'Diagnostic en cours' if active else 'En attente de tests'
        data['count'] = str(max(0, int(view.get('completed_tests', 0)))) + ' test(s) terminé(s)'
        data['remaining'] = format_authorization_duration(view.get('authorization_remaining_seconds'))
        if state['closing']:
            data['application'] = 'ARRÊT EN COURS'
        for key, _ in rows:
            text = str(data.get(key, 'EN ATTENTE'))[:100]
            tone = badge_tone(text) if key not in ('count', 'remaining') else 'normal'
            styles[values[key]] = (tone, tone if tone in backgrounds else 'white')
            user.SetWindowTextW(values[key], text)
        for prefix, source in [('current', 'current_metrics'), ('average', 'session_metrics')]:
            for key, unit in [('jitter_ms', 'ms'), ('loss_percent', '%'), ('rms_dbfs', 'dBFS'), ('audio_gap_s', 's')]:
                user.SetWindowTextW(controls[prefix+'_'+key], metric_text((view.get(source) or {}).get(key), unit))
        user.SetWindowTextW(controls['ticket'], ticket_title(view))
        user.SetWindowTextW(controls['version'], 'Agent ' + str(view.get('version', ''))[:32] + (' · VERSION DE TEST — NON SIGNÉE AUTHENTICODE' if lab else ''))
        user.SetWindowTextW(controls['error'], str(view.get('diagnostic_message') or view.get('error') or '')[:150])
        title, message, tone = client_notice(view, closing=state['closing'])
        styles[controls['notice_title']] = (tone, 'white')
        user.SetWindowTextW(controls['notice_title'], title)
        user.SetWindowTextW(controls['notice_body'], message)
        if state['notice_tone'] != tone:
            state['notice_tone'] = tone
            user.InvalidateRect(hwnd, None, False)
        expired = 'EXPIRÉ' in str(view.get('adoption', ''))
        user.SetWindowTextW(controls['quit'], 'Fermer' if expired else 'Quitter')
        tip = tray_tooltip(view)
        if state['tray'] and tip != state['tip']:
            notification = tray_data(hwnd)
            notification.uFlags, notification.szTip = 4|0x80, tip
            shell.Shell_NotifyIconW(1, ctypes.byref(notification))
            state['tip'] = tip
        if smoke_seconds is not None and time.monotonic()-state['started'] >= smoke_seconds:
            begin_close(hwnd, confirm=False)
        # A confirmed intervention end stops the SIP worker without a GUI
        # click. Close its window as well; keep startup errors visible.
        if worker_done.is_set() and not state['closing'] and view.get('application') != 'ERREUR':
            begin_close(hwnd, confirm=False)
        if state['closing'] and worker_done.is_set():
            user.DestroyWindow(hwnd)

    @WNDPROC
    def window_proc(hwnd, message, wp, lp):
        if message == 0x0010:
            begin_close(hwnd)
            return 0
        if message == 0x0111:
            command = wp & 0xffff
            if command == 1001:
                begin_close(hwnd)
            elif command == 1002:
                minimize_to_tray(hwnd)
            elif command == 1003:
                restore(hwnd)
            return 0
        if message == callback_message:
            action = lp & 0xffff
            if action in (0x0202, 0x0203, 0x0400, 0x0401, 0x0405):
                restore(hwnd)
            elif action in (0x0205, 0x007B):
                context_menu(hwnd)
            return 0
        if taskbar_created and message == taskbar_created:
            state['tray'] = False
            if not add_tray(hwnd) and state['hidden']:
                restore(hwnd)
            return 0
        if message == 0x0113:
            refresh(hwnd)
            return 0
        if message == 0x0138:
            tone, background = styles.get(lp, ('normal', 'white'))
            gdi.SetBkMode(wp, 1)
            gdi.SetTextColor(wp, color(foregrounds.get(tone, foregrounds['normal'])))
            return brushes[background]
        if message == 0x000F:
            paint = PAINTSTRUCT()
            dc = user.BeginPaint(hwnd, ctypes.byref(paint))
            if dc:
                def rectangle(x, y, width, height, brush):
                    rect = w.RECT(px(x), px(y), px(x+width), px(y+height))
                    user.FillRect(dc, ctypes.byref(rect), brushes[brush])
                rectangle(0, 0, 620, 105, 'white')
                rectangle(0, 0, 620, 5, 'brand')
                old_pen = gdi.SelectObject(dc, gdi.GetStockObject(8))
                old_brush = gdi.SelectObject(dc, brushes['white'])
                for y, height in ((143, 208), (356, 143), (507, 173)):
                    gdi.RoundRect(dc, px(22), px(y), px(598), px(y+height), px(16), px(16))
                gdi.SelectObject(dc, old_brush)
                gdi.SelectObject(dc, old_pen)
                rectangle(22, 519, 4, 145, state['notice_tone'])
            user.EndPaint(hwnd, ctypes.byref(paint))
            return 0
        if message == 0x0002:
            remove_tray(hwnd)
            user.KillTimer(hwnd, 1)
            user.PostQuitMessage(0)
            return 0
        return user.DefWindowProcW(hwnd, message, wp, lp)

    cls = WNDCLASS(0, window_proc, 0, 0, instance, large_icon, user.LoadCursorW(None, ctypes.c_void_p(32512)), brushes['page'], None, class_name)
    registered, hwnd = False, None
    try:
        if not user.RegisterClassW(ctypes.byref(cls)):
            raise OSError('Création de la fenêtre WIFX impossible.')
        registered = True
        # Caption, system menu and standard minimize box; no maximize or resize.
        hwnd = user.CreateWindowExW(0, class_name, 'WIFX Voice Probe — Sonde de diagnostic', 0x00CA0000,
                                     left, top, outer_width, outer_height, None, None, instance, None)
        if not hwnd:
            raise OSError('Création de la fenêtre WIFX impossible.')
        user.SendMessageW(hwnd, 0x0080, 0, small_icon)
        user.SendMessageW(hwnd, 0x0080, 1, large_icon)
        def control(kind, text, x, y, width, height, identifier=0, font=normal_font, extra=0, background='white'):
            child = user.CreateWindowExW(0, kind, text, 0x50000000|extra, px(x), px(y), px(width), px(height), hwnd, identifier or None, instance, None)
            if not child:
                raise OSError('Création de l’interface WIFX impossible.')
            user.SendMessageW(child, 0x0030, font, 1)
            styles[child] = ('normal', background)
            return child
        logo = control('STATIC', '', 28, 31, 120, 49, extra=0x0E)
        user.SendMessageW(logo, 0x0172, 0, bitmap)
        control('STATIC', 'WIFX VOICE PROBE', 171, 28, 400, 31, font=title_font)
        control('STATIC', 'Sonde de diagnostic téléphonique', 173, 66, 390, 25, font=small_font)
        controls['ticket'] = control('STATIC', 'Intervention WIFX', 27, 113, 560, 25, font=bold_font, background='page')
        for index, (key, label) in enumerate(rows):
            y = 153+index*24
            control('STATIC', label, 39, y, 215, 23)
            values[key] = control('STATIC', 'EN ATTENTE', 263, y-1, 315, 23, font=small_bold, extra=1)
        control('STATIC', 'Mesures', 38, 364, 180, 23, font=small_bold)
        control('STATIC', 'Test(s) en cours', 220, 364, 174, 23, font=small_bold)
        control('STATIC', 'Moyenne de la session', 403, 364, 183, 23, font=small_bold)
        for index, (key, label) in enumerate([('jitter_ms','Jitter RTP moyen'), ('loss_percent','Pertes RTP'), ('rms_dbfs','Niveau audio reçu'), ('audio_gap_s','Interruptions audio')]):
            y = 392+index*24
            control('STATIC', label, 38, y, 180, 23, font=small_font)
            controls['current_'+key] = control('STATIC', '—', 220, y, 174, 23, font=small_font)
            controls['average_'+key] = control('STATIC', '—', 403, y, 183, 23, font=small_font)
        controls['notice_title'] = control('STATIC', '', 40, 523, 530, 23, font=small_bold)
        controls['notice_body'] = control('STATIC', '', 40, 553, 530, 117, font=small_font)
        controls['error'] = control('STATIC', '', 28, 689, 555, 42, font=small_font, background='page')
        styles[controls['error']] = ('neutral', 'page')
        controls['version'] = control('STATIC', '', 28, 735, 560, 38, font=small_font, background='page')
        controls['minimize'] = control('BUTTON', 'Réduire', 382, 772, 98, 30, 1002, small_font)
        controls['quit'] = control('BUTTON', 'Quitter', 490, 772, 98, 30, 1001, small_font)
        user.ShowWindow(hwnd, 5)
        user.UpdateWindow(hwnd)
        add_tray(hwnd)
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
            remove_tray(hwnd)
            user.DestroyWindow(hwnd)
        if registered:
            user.UnregisterClassW(class_name, instance)
        for resource in fonts+list(brushes.values())+[bitmap]:
            if resource:
                gdi.DeleteObject(resource)
        for resource in (small_icon, large_icon):
            if resource:
                user.DestroyIcon(resource)
