"""Explicit EXE cleanup policy; native CNG integration has dedicated Windows tests."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

WINDOWS=Path(__file__).resolve().parents[1]/'windows'
sys.path[:0]=[str(WINDOWS),str(WINDOWS.parent/'src')]
spec=importlib.util.spec_from_file_location('portable_entry',WINDOWS/'portable-entry.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
from portable_runtime import PortableError


class CleanupTests(unittest.TestCase):
    def test_no_confirmation_does_not_open_identity_or_claim_success(self):
        ask=Mock(return_value=False);notify=Mock();factory=Mock()
        self.assertEqual(entry.forget_identity({'mode':'persistent'},ask,notify,identity_factory=factory),2)
        ask.assert_called_once();factory.assert_not_called();notify.assert_not_called()

    def test_confirmed_cleanup_opens_only_verified_instance_without_creation(self):
        provision={'mode':'persistent','instance_id':'one-verified-instance'}
        identity=Mock();factory=Mock(return_value=identity);notify=Mock()
        self.assertEqual(entry.forget_identity(provision,Mock(return_value=True),notify,identity_factory=factory),0)
        factory.assert_called_once_with(provision,allow_create=False)
        identity.forget.assert_called_once_with();identity.close.assert_called_once_with();notify.assert_called_once()

    def test_failed_or_active_identity_is_never_reported_deleted(self):
        identity=Mock();identity.forget.side_effect=PortableError('Nettoyage refusé.')
        notify=Mock()
        with self.assertRaises(PortableError):
            entry.forget_identity({'mode':'persistent'},Mock(return_value=True),notify,identity_factory=Mock(return_value=identity))
        identity.close.assert_called_once();notify.assert_not_called()
        factory=Mock(side_effect=PortableError('Identité déjà utilisée.'))
        with self.assertRaises(PortableError):
            entry.forget_identity({'mode':'persistent'},Mock(return_value=True),notify,identity_factory=factory)
        notify.assert_not_called()

    def test_ephemeral_mode_does_not_open_an_instance(self):
        factory=Mock();ask=Mock();notify=Mock()
        with self.assertRaises(PortableError):entry.forget_identity({'mode':'ephemeral'},ask,notify,identity_factory=factory)
        factory.assert_not_called();ask.assert_not_called();notify.assert_not_called()

    def test_native_confirmation_defaults_to_no(self):
        import ast
        tree=ast.parse((WINDOWS/'portable-entry.py').read_text())
        dialogs=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='native_forget_dialogs')
        ask=next(n for n in dialogs.body if isinstance(n,ast.FunctionDef) and n.name=='ask')
        call=next(n for n in ast.walk(ask) if isinstance(n,ast.Call))
        flags=eval(compile(ast.Expression(call.args[-1]),'<flags>','eval'),{'__builtins__':{}})
        self.assertEqual(flags&0xF,4)
        self.assertEqual(flags&0xF00,0x100)


if __name__=='__main__':unittest.main()
