"""Run against an existing local image, using its modules and generated test-only keys."""

import hashlib
import os
from pathlib import Path
import sys
import unittest

runtime = Path("/opt/lab")
checks = Path(__file__).parent
if sys.platform != "linux" or os.geteuid() != 10001:
    raise SystemExit("Offline image verification requires Linux UID10001")
for name in ("app.py", "generate_lab.py", "lab_protocol.py", "lab_state.py",
             "operator_control.py", "deploy_support.py", "gunicorn.conf.py"):
    if hashlib.sha256((runtime / name).read_bytes()).digest() != hashlib.sha256((checks / name).read_bytes()).digest():
        raise SystemExit("Image/source mismatch: " + name)
source = Path(os.environ["SAS_SOURCE"])
expected_source = checks.parents[1] / "CBRS_Mock_SAS_Python_Master" / "cbrsPython-master"
for folder in ("cbrsPython/model", "Configuration", "jsonExpectedFolder"):
    for path in (source / folder).rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts:
            relative = path.relative_to(source)
            if path.read_bytes() != (expected_source / relative).read_bytes():
                raise SystemExit("Original handler/scenario image mismatch")
sys.path.insert(0, str(runtime))
import app
import test_lab

if Path(app.__file__).parent != runtime:
    raise SystemExit("Verification did not import the exact image runtime")
suite = unittest.defaultTestLoader.loadTestsFromModule(test_lab)
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
