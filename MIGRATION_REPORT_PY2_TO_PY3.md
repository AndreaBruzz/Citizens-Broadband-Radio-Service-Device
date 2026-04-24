# Python 2.7 → 3.11 Migration Report — CBRS Mock SAS

## Summary

This report identifies all Python 2.7-specific code patterns across the project that must be changed to run on Python 3.11. The changes are grouped by category, with affected files and line-level details.

---

## 1. `print` Statement → `print()` Function

Python 2 `print` is a statement; Python 3 requires it as a function call.

| File | Line(s) | Current Code | Required Change |
|------|---------|-------------|-----------------|
| `cbrsPython/Loggers/CmdLogger.py` | ~60 | `print message` | `print(message)` |
| `cbrsPython/Loggers/XmlLogger.py` | ~148 | `print "the folder : " + folder_Name + ...` | `print("the folder : " + folder_Name + ...)` |
| `cbrsPython/controllers/StartPowerMeas.py` | ~82 | `print('To stop the test session...')` | Already uses function syntax ✅ |
| `cbrsPython/controllers/gui.py` | ~68 | `print( self.tkvar.get() )` | Already uses function syntax ✅ |

---

## 2. `raw_input()` → `input()`

`raw_input()` was removed in Python 3. Use `input()` instead.

| File | Line(s) | Occurrences |
|------|---------|-------------|
| `cbrsPython/controllers/CLIHandler.py` | ~103, ~113, ~118, ~123 | 4 calls to `raw_input()` |
| `cbrsPython/controllers/StartOfProject.py` | ~38, ~43, ~50, ~53, ~82 | 5 calls to `raw_input()` |
| `cbrsPython/controllers/StartPowerMeas.py` | ~84 | 1 call to `raw_input()` |
| `cbrsPython/controllers/CLIUtils/QuestionHandler.py` | ~40, ~45 | 2 calls to `raw_input()` |
| `cbrsPython/Loggers/XmlLogger.py` | ~149 | 1 call to `raw_input()` |

---

## 3. `dict.iteritems()` → `dict.items()`

`iteritems()` was removed in Python 3. Use `items()` instead.

| File | Line(s) | Context |
|------|---------|---------|
| `cbrsPython/model/powerMeasRequestHandler.py` | ~88 | `for key, value in httpRequest.iteritems():` |
| `cbrsPython/model/powerMeasRequestHandler.py` | ~112 | `for item in jsonAfterParse.iteritems():` |
| `cbrsPython/model/CBRSRequestHandler.py` | ~195 | `for item in jsonAfterParse.iteritems():` |
| `cbrsPython/model/Utils/Assert.py` | ~163 | `for key, value in httpRequest.iteritems():` |
| `cbrsPython/model/Utils/Assert.py` | ~183 | `for key2, value2 in httpRequest[key].iteritems():` |
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | ~178 | `for value in expected.iteritems():` |

---

## 4. `from __builtin__ import True` — Removed Module

The `__builtin__` module was renamed to `builtins` in Python 3. However, importing `True` is completely unnecessary in both Python 2.7+ and Python 3 — `True` is a keyword. **Remove these imports entirely.**

| File | Line |
|------|------|
| `cbrsPython/model/flaskServer.py` | `from __builtin__ import True` |
| `cbrsPython/model/with_end_slash_flaskServer.py` | `from __builtin__ import True` |
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | `from __builtin__ import True` |

---

## 5. `Exception.message` → `str(e)` or `e.args[0]`

Python 3 removed the `.message` attribute from exceptions. Use `str(e)` or `e.args[0]`.

| File | Line(s) | Current Code |
|------|---------|-------------|
| `cbrsPython/model/CBRSRequestHandler.py` | ~175 | `if e.message == "node not exists":` |
| `cbrsPython/model/Engine.py` | ~55 | `return E.message` |
| `cbrsPython/model/Engine.py` | ~62 | `return ... E.message` |
| `cbrsPython/model/Engine.py` | ~73 | `return E.message` |
| `cbrsPython/model/powerMeasEngine.py` | ~57 | `return E.message` |
| `cbrsPython/model/powerMeasEngine.py` | ~68 | `return ... E.message` |
| `cbrsPython/model/powerMeasEngine.py` | ~82 | `return E.message` |
| `cbrsPython/model/powerMeasRequestHandler.py` | ~107 | `if e.message == "node not exists":` |
| `cbrsPython/model/Utils/Assert.py` | ~52 | `raise IOError(e.message)` |
| `cbrsPython/model/Utils/Assert.py` | ~130 | `return E.message` |
| `cbrsPython/controllers/CLIHandler.py` | ~97 | `loggerHandler.print_To_Terminal(e.message)` |
| `cbrsPython/controllers/StartOfProject.py` | ~72 | `loggerHandler.print_To_Terminal(e.message)` |
| `cbrsPython/controllers/StartOfProject.py` | ~81 | `loggerHandler.print_To_Terminal(E.message)` |

**Fix pattern:**
```python
# Before
except Exception as e:
    if e.message == "node not exists":

# After
except Exception as e:
    if str(e) == "node not exists":
    # or: if e.args and e.args[0] == "node not exists":
```

---

## 6. `xrange()` → `range()`

`xrange()` was removed in Python 3. Use `range()`.

| File | Line(s) |
|------|---------|
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | ~93 (`_is_list_same`) |
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | ~99 (`_bottom_up_sort`) |

---

## 7. Removed Built-in Types: `long`, `unicode`

Python 3 unified `int`/`long` into `int` and `str`/`unicode` into `str`.

| File | Line | Current Code | Required Change |
|------|------|-------------|-----------------|
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | ~128 | `if type(expected) in (int, str, bool, long, float, unicode):` | Change to `(int, str, bool, float)` |

---

## 8. `from Tkinter import *` → `from tkinter import *`

The Tkinter module was renamed to lowercase in Python 3.

| File | Line | Current Code | Required Change |
|------|------|-------------|-----------------|
| `cbrsPython/controllers/gui.py` | ~14 | `from Tkinter import *` | `from tkinter import *` |
| `cbrsPython/controllers/gui.py` | ~14 | `import tkMessageBox` | `from tkinter import messagebox` |

Also: `Image.ANTIALIAS` was removed in Pillow 10+. Use `Image.LANCZOS` instead (line ~39).

---

## 9. `import commands` → `import subprocess`

The `commands` module was removed in Python 3.

| File | Line |
|------|------|
| `cbrsPython/Loggers/XmlLogger.py` | `import commands` |

This import appears unused, so it can simply be removed.

---

## 10. `OrderedDict` Internal Access (`__root`, `__map`)

The `ordered_dict_prepend` function in `JsonComparisonUtils.py` accesses private internals of `OrderedDict` (`_OrderedDict__root`, `_OrderedDict__map`). These internals changed in Python 3.

| File | Function |
|------|----------|
| `cbrsPython/model/Utils/JsonComparisonUtils.py` | `ordered_dict_prepend()` |

**Required rewrite:**
```python
def ordered_dict_prepend(dct, key, value, dict_setitem=dict.__setitem__):
    if key in dct:
        del dct[key]
    # Rebuild with new key first
    items = list(dct.items())
    dct.clear()
    dict_setitem(dct, key, value)
    for k, v in items:
        dict_setitem(dct, k, v)
```

---

## 11. `dict.next()` → `next(iterator)`

| File | Line | Current Code | Required Change |
|------|------|-------------|-----------------|
| `cbrsPython/controllers/CLIUtils/CsvFileParser.py` | ~60 | `return len(reader.next())` | `return len(next(reader))` |

---

## 12. `input()` Behavior Change (Python 2 `input()` = `eval()`)

In Python 2, `input()` evaluates the expression. In Python 3, `input()` returns a string (like Python 2's `raw_input()`). The following uses of Python 2 `input()` rely on automatic numeric evaluation and need explicit `int()` or `float()` conversion:

| File | Line(s) | Current Code | Required Change |
|------|---------|-------------|-----------------|
| `cbrsPython/controllers/StartPowerMeas.py` | ~119 | `frequency = input(...)` | `frequency = int(input(...))` |
| `cbrsPython/controllers/StartPowerMeas.py` | ~131 | `BWinput = input(...)` | `BWinput = int(input(...))` |
| `cbrsPython/controllers/StartPowerMeas.py` | ~132 | `numOfCarriers = input(...)` | `numOfCarriers = int(input(...))` |
| `cbrsPython/controllers/StartPowerMeas.py` | ~152 | `eirpInput = input(...)` | `eirpInput = float(input(...))` |

---

## 13. `ssl.PROTOCOL_TLSv1_2` Deprecation

`ssl.PROTOCOL_TLSv1_2` is deprecated in Python 3.10+. Use `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` or `ssl.create_default_context()` with minimum version set.

| File | Line(s) |
|------|---------|
| `cbrsPython/controllers/StartOfProject.py` | ~93 |
| `cbrsPython/controllers/StartPowerMeas.py` | ~186 |

**Recommended replacement:**
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
```

---

## 14. `jwt.decode()` API Changes

The PyJWT library (v2.x+) changed its API. `verify=False` is no longer accepted; use `options={"verify_signature": False}` and `algorithms` is now required.

| File | Line(s) | Current Code |
|------|---------|-------------|
| `cbrsPython/model/CBRSRequestHandler.py` | ~260 | `jwt.decode(encoded_cpi_data, verify=False)` |
| `cbrsPython/model/CBRSRequestHandler.py` | ~270 | `jwt.decode(encoded_cpi_data, cpi_public_key, algorithms=...)` |

**Required changes:**
```python
# Before
jwt.decode(encoded_cpi_data, verify=False)

# After (PyJWT 2.x)
jwt.decode(encoded_cpi_data, options={"verify_signature": False}, algorithms=consts.CPI_SIGNATURE_VALID_TYPES)

# Before
jwt.decode(encoded_cpi_data, cpi_public_key, algorithms=consts.CPI_SIGNATURE_VALID_TYPES)

# After (PyJWT 2.x)
jwt.decode(encoded_cpi_data, cpi_public_key, algorithms=consts.CPI_SIGNATURE_VALID_TYPES)
# (this form is compatible, but ensure key is passed as keyword arg if needed)
```

---

## 15. `cryptography.hazmat.backends.default_backend()` Deprecated

Since `cryptography` >= 3.x, `default_backend()` is no longer needed. `load_pem_x509_certificate()` no longer requires a backend argument.

| File | Line(s) |
|------|---------|
| `cbrsPython/model/CBRSRequestHandler.py` | ~265 |
| `cbrsPython/model/powerMeasRequestHandler.py` | ~23 |

**Change:**
```python
# Before
cpi_cert_obj = load_pem_x509_certificate(cpi_cert, default_backend())

# After
cpi_cert_obj = load_pem_x509_certificate(cpi_cert.encode())
```

---

## 16. String/Bytes Handling

In Python 3, `open()` returns `str` by default, and `request.data` in Flask returns `bytes`. Ensure proper encoding/decoding.

| File | Context | Required Change |
|------|---------|-----------------|
| `cbrsPython/model/flaskServer.py` | `json.loads(request.data, ...)` | In Flask 2.x+ `request.data` is bytes; `json.loads()` handles bytes in Py3, but `request.get_json()` is preferred |
| `cbrsPython/model/with_end_slash_flaskServer.py` | Same as above | Same fix |
| `cbrsPython/controllers/StartPowerMeas.py` | Same as above | Same fix |
| `cbrsPython/model/CBRSRequestHandler.py` | `cpi_cert = open(..., 'r').read()` then passed to `load_pem_x509_certificate()` | Read as bytes: `open(..., 'rb').read()` |

---

## 17. `click.decorators` Import

| File | Line |
|------|------|
| `cbrsPython/model/Utils/Assert.py` | `from click.decorators import option` |

This import appears unused. Remove it. If `click` is not in your dependencies, this will cause an `ImportError`.

---

## 18. Relative vs Absolute Imports

Several files use implicit relative imports (Python 2 style). Python 3 requires explicit relative imports.

| File | Current Import | Required Change |
|------|---------------|-----------------|
| `cbrsPython/controllers/CLIHandler.py` | `from CLIUtils.CsvFileParser import CsvFileParser` | `from controllers.CLIUtils.CsvFileParser import CsvFileParser` or `from .CLIUtils.CsvFileParser import CsvFileParser` |
| `cbrsPython/controllers/CLIHandler.py` | `from ENodeBController import ENodeBController` | `from controllers.ENodeBController import ENodeBController` or `from .ENodeBController import ENodeBController` |
| `cbrsPython/model/flaskServer.py` | `import Utils.Consts as consts` | `import model.Utils.Consts as consts` |
| `cbrsPython/model/flaskServer.py` | `from controllers.ENodeBController import ...` | Verify path is correct from execution context |
| `cbrsPython/model/with_end_slash_flaskServer.py` | `import Utils.Consts as consts` | `import model.Utils.Consts as consts` |
| `cbrsPython/controllers/StartPowerMeas.py` | `from Loggers.LoggerObserver import loggerObserver` | `from Loggers.LoggerObserver import loggerObserver` (verify with package structure) |
| `cbrsPython/Loggers/CmdLogger.py` | `from Loggers.LogObserver import Observer` | May need adjustment depending on how the project is run |

> **Note:** The exact fix depends on whether the project uses a proper package structure with `__init__.py` and how the entry points are invoked. A consistent approach is to make `cbrsPython` the root package and use absolute imports from there, or use relative imports with leading dots.

---

## 19. `threading.Event` — `_stop` Attribute Conflict

| File | Line(s) |
|------|---------|
| `cbrsPython/controllers/CLIHandler.py` | `self._stop = threading.Event()` |
| `cbrsPython/controllers/StartPowerMeas.py` | `self._stop = threading.Event()` |

In Python 3, `Thread` has a `_stop` method internally. Using `self._stop` as an attribute name can conflict. Rename to `self._stop_event`.

---

## 20. `dict` Iteration While Modifying

| File | Context |
|------|---------|
| `cbrsPython/model/CBRSRequestHandler.py` | `for item in jsonAfterParse.iteritems(): del jsonAfterParse[item[0]]` |
| `cbrsPython/model/powerMeasRequestHandler.py` | Same pattern |

In Python 3, you cannot modify a dict while iterating over it. Collect keys to delete first:

```python
keys_to_delete = [k for k in jsonAfterParse if k != typeOfCalling + consts.RESPONSE_NODE_NAME.title()]
for k in keys_to_delete:
    del jsonAfterParse[k]
```

---

## 21. `werkzeug.server.shutdown` Removed

The `werkzeug.server.shutdown` environ key was removed in Werkzeug 2.x (used with Flask 2.x+).

| File | Line(s) |
|------|---------|
| `cbrsPython/model/with_end_slash_flaskServer.py` | `func = request.environ.get(consts.NAME_OF_SERVER_WERKZUG)` then `func()` |
| `cbrsPython/controllers/StartPowerMeas.py` | Same pattern |

**Alternative:** Use `signal` or run Flask in a thread and stop it externally, or use `multiprocessing` to terminate the server process.

---

## 22. Syntax Error (Pre-existing)

| File | Line |
|------|------|
| `cbrsPython/controllers/StartPowerMeas.py` | ~132 | 

```python
 numOfCarriers = input(...)   # leading space causes IndentationError
```

This line has a leading space that will cause an `IndentationError`. Fix the indentation.

---

## File-by-File Change Summary

| File | Changes Required |
|------|-----------------|
| `model/powerMeasRequestHandler.py` | `.iteritems()` → `.items()`, `e.message` → `str(e)`, dict-while-iterating fix, remove `default_backend` |
| `model/CBRSRequestHandler.py` | `.iteritems()` → `.items()`, `e.message` → `str(e)`, dict-while-iterating fix, `jwt.decode` API, `open('rb')`, `default_backend` removal |
| `model/Engine.py` | `E.message` → `str(E)` (6 occurrences) |
| `model/powerMeasEngine.py` | `E.message` → `str(E)` (3 occurrences) |
| `model/flaskServer.py` | Remove `from __builtin__ import True`, `print` → `print()`, fix relative imports |
| `model/with_end_slash_flaskServer.py` | Remove `from __builtin__ import True`, fix relative imports, remove `werkzeug.server.shutdown` usage |
| `model/Utils/JsonComparisonUtils.py` | Remove `from __builtin__ import True`, `xrange` → `range`, remove `long`/`unicode`, rewrite `ordered_dict_prepend`, `.iteritems()` → `.items()` |
| `model/Utils/Assert.py` | `.iteritems()` → `.items()`, `e.message` → `str(e)`, remove unused `click` import |
| `model/Utils/Consts.py` | No changes needed ✅ |
| `controllers/CLIHandler.py` | `raw_input()` → `input()`, fix relative imports, rename `_stop` |
| `controllers/StartOfProject.py` | `raw_input()` → `input()`, `E.message` → `str(E)`, `ssl.PROTOCOL_TLSv1_2` update |
| `controllers/StartPowerMeas.py` | `raw_input()` → `input()`, `input()` → `int(input())` for numeric inputs, `ssl.PROTOCOL_TLSv1_2` update, fix indentation error, rename `_stop` |
| `controllers/gui.py` | `Tkinter` → `tkinter`, `tkMessageBox` → `tkinter.messagebox`, `Image.ANTIALIAS` → `Image.LANCZOS` |
| `controllers/ENodeBController.py` | No changes needed ✅ |
| `controllers/CLIUtils/CsvFileParser.py` | `reader.next()` → `next(reader)` |
| `controllers/CLIUtils/QuestionHandler.py` | `raw_input()` → `input()` |
| `controllers/CLIUtils/TestDefinition.py` | No changes needed ✅ |
| `controllers/CLIUtils/enums.py` | No changes needed ✅ |
| `controllers/CLIUtils/Step.py` | No changes needed ✅ |
| `Loggers/LoggerObserver.py` | No changes needed ✅ |
| `Loggers/LogObserver.py` | No changes needed ✅ |
| `Loggers/CmdLogger.py` | `print message` → `print(message)` |
| `Loggers/DebugLogger.py` | No changes needed ✅ |
| `Loggers/XmlLogger.py` | `import commands` → remove, `print` → `print()`, `raw_input()` → `input()` |

---

## Dependency Updates Required

Update `requirements.txt` (or create one) with Python 3.11-compatible versions:

| Package | Minimum Version for Py3.11 |
|---------|---------------------------|
| `flask` | >= 2.3 |
| `werkzeug` | >= 2.3 |
| `PyJWT` | >= 2.0 |
| `cryptography` | >= 41.0 |
| `jsonschema` | >= 4.0 |
| `Pillow` | >= 10.0 (if using gui.py) |
| `pathlib` | Built-in in Python 3 (remove from deps if listed) |
| `enum` | Built-in in Python 3.4+ (remove `enum34` if listed) |

---

## Recommended Migration Order

1. **Fix syntax/import errors** — `__builtin__`, relative imports, `commands`, `click`
2. **Fix language-level changes** — `print`, `raw_input`, `xrange`, `long`/`unicode`, `.iteritems()`, `.next()`, `e.message`
3. **Fix dict mutation during iteration** — `process_response` methods
4. **Fix `OrderedDict` internals** — `ordered_dict_prepend`
5. **Fix library API changes** — `jwt.decode`, `cryptography`, `ssl`, `werkzeug` shutdown
6. **Fix GUI module** — `Tkinter` → `tkinter`
7. **Test end-to-end** with Python 3.11
