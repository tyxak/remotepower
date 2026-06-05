"""Load-order smoke check for the split client JS.

Concatenates every static/js/*.js in index.html declaration order and evaluates
it under a permissive DOM stub in V8 (py_mini_racer). The stub makes every
browser API call succeed, so the ONLY thing that throws is a genuine
load-time ReferenceError — i.e. a function or top-level let/const that was
moved to a later file but is referenced at load time by an earlier one. That's
exactly the failure mode an app.js split can introduce and that the
grep-based tests can't catch.

Run directly: python3 tests/_jsload_harness.py
"""
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_JS_DIR = _ROOT / "server" / "html" / "static" / "js"
_INDEX = _ROOT / "server" / "html" / "index.html"

_STUB = r"""
// Permissive universal proxy: any get/call/construct yields itself, any set ok.
var __P = new Proxy(function(){}, {
  get: function(t,k){ if (k === Symbol.toPrimitive) return function(){return ''}; return __P; },
  apply: function(){ return __P; },
  construct: function(){ return __P; },
  set: function(){ return true; },
  has: function(){ return true; },
});
var window = __P, document = __P, navigator = __P, location = __P;
var localStorage = __P, sessionStorage = __P, history = __P;
var addEventListener = function(){}, removeEventListener = function(){};
var setInterval = function(){return 0}, clearInterval = function(){};
var setTimeout = function(){return 0}, clearTimeout = function(){};
var requestAnimationFrame = function(){return 0}, cancelAnimationFrame = function(){};
var fetch = function(){return __P};
var MutationObserver = function(){return __P};
var WebSocket = function(){return __P};
var URL = function(){return __P};
var alert = function(){}, confirm = function(){return true}, prompt = function(){return ''};
var requestIdleCallback = function(){return 0};
var getComputedStyle = function(){return __P};
var matchMedia = function(){return __P};
var Notification = function(){return __P};
var URLSearchParams = function(){return __P};
var FormData = function(){return __P};
var Blob = function(){return __P};
var File = function(){return __P};
var FileReader = function(){return __P};
var Image = function(){return __P};
var XMLHttpRequest = function(){return __P};
var EventSource = function(){return __P};
var btoa = function(){return ''}, atob = function(){return ''};
var structuredClone = function(x){return x};
var crypto = __P;
var performance = __P;
"""


def _load_order():
    html = _INDEX.read_text()
    order = []
    for m in re.finditer(r'<script\s+(?:defer\s+)?src="static/js/([A-Za-z0-9_.\-]+)(?:\?[^"]*)?"', html):
        if m.group(1) not in order:
            order.append(m.group(1))
    for f in sorted(_JS_DIR.glob("*.js")):
        if f.name not in order:
            order.append(f.name)
    return order


def concat():
    parts = [_STUB]
    for name in _load_order():
        f = _JS_DIR / name
        if f.is_file():
            parts.append(f"\n// ===== {name} =====\n" + f.read_text())
    return "\n".join(parts)


def check():
    from py_mini_racer import MiniRacer
    ctx = MiniRacer()
    try:
        ctx.eval(concat())
        return None
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    err = check()
    if err:
        print("LOAD ERROR:\n" + err)
        sys.exit(1)
    print("client JS loads clean in declaration order (no load-time ReferenceError)")
