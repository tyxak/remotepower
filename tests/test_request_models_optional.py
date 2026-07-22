"""The pydantic pilot must stay OPTIONAL.

request_models documents pydantic as an optional dependency ("handlers
unchanged" when it is absent) and validate() honours that. But the ~212 call
sites resolve the model EAGERLY — `_read_valid(request_models.SomeRequest)` —
so on a host WITHOUT pydantic that attribute lookup raised AttributeError and
500'd the handler before validate() ever ran. This pins the module-level
__getattr__ fallback that keeps the documented contract true.

The no-pydantic case is reproduced faithfully by blocking the import at module
exec time (sys.modules['pydantic'] = None makes `from pydantic import ...`
raise ImportError), so the model classes are genuinely never defined — merely
flipping _AVAILABLE afterwards would not exercise __getattr__ at all.
"""
import importlib.machinery
import importlib.util
import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'request_models.py'
_MISSING = object()


def _load(without_pydantic):
    saved = sys.modules.get('pydantic', _MISSING)
    if without_pydantic:
        sys.modules['pydantic'] = None       # -> ImportError on `from pydantic import`
    try:
        ldr = importlib.machinery.SourceFileLoader('request_models_t', str(_SRC))
        spec = importlib.util.spec_from_loader('request_models_t', ldr)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        if without_pydantic:
            if saved is _MISSING:
                sys.modules.pop('pydantic', None)
            else:
                sys.modules['pydantic'] = saved


class TestWithoutPydantic(unittest.TestCase):
    """Exactly the server that 500'd: library absent at import time."""

    def setUp(self):
        self.rm = _load(without_pydantic=True)
        self.assertFalse(self.rm.available(), 'fixture failed to hide pydantic')

    def test_model_resolves_to_none_instead_of_raising(self):
        # THE REGRESSION: this attribute access raised AttributeError -> 500.
        for name in ('CheckBaselineApplyRequest', 'CustomChecksSaveRequest',
                     'HeartbeatRequest', 'SomeFutureRequest'):
            self.assertIsNone(getattr(self.rm, name),
                              f'{name} must resolve to None, not raise')

    def test_validate_is_a_noop(self):
        model = self.rm.CheckBaselineApplyRequest        # None
        self.assertEqual(self.rm.validate(model, {'ids': ['agent_running'],
                                                  'target_kind': 'host',
                                                  'target': 'd1'}), (True, None))
        # a non-dict body must not raise either
        self.assertEqual(self.rm.validate(model, ['not', 'a', 'dict']), (True, None))

    def test_non_model_attribute_still_raises(self):
        with self.assertRaises(AttributeError):
            _ = self.rm.definitely_not_a_model


class TestWithPydantic(unittest.TestCase):
    def setUp(self):
        self.rm = _load(without_pydantic=False)
        if not self.rm.available():
            self.skipTest('pydantic not installed in this environment')

    def test_real_models_still_validate(self):
        model = self.rm.CheckBaselineApplyRequest
        self.assertIsNotNone(model)
        ok, err = self.rm.validate(model, {'ids': ['a'], 'target_kind': 'host',
                                           'target': 'd1'})
        self.assertTrue(ok, err)

    def test_bad_body_is_still_rejected(self):
        ok, err = self.rm.validate(self.rm.CheckBaselineApplyRequest, {'ids': 'nope'})
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_getattr_fallback_is_not_consulted(self):
        # real class found by normal lookup, so __getattr__ never fires
        self.assertTrue(isinstance(self.rm.CheckBaselineApplyRequest, type))


if __name__ == '__main__':
    unittest.main()
