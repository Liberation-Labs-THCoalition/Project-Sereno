"""Python startup hooks (2026-10-23): .pth import lines and sitecustomize/usercustomize, with normal ones allowed."""
import pytest

from sentinel import scanner
from sentinel.scanner import pth_verdict, _startup_files


@pytest.mark.parametrize("name,content", [
    ("_virtualenv.pth", "import _virtualenv\n"),
    ("distutils-precedence.pth", "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var)\n"),
    ("__editable__.emet-0.1.0.pth",
     "import __editable___emet_0_1_0_finder; __editable___emet_0_1_0_finder.install()\n"),
    ("a1_coverage.pth", "import sys; exec('import os\\nif os.getenv(\"COVERAGE_PROCESS_START\"): pass')\n"),
    ("pytest-cov.pth", "import os, sys;exec('if \\'COV_CORE_SOURCE\\' in os.environ: pass')\n"),
    ("zope.interface-5.0-nspkg.pth", "import sys, types, os;has_mfs = sys.version_info > (3, 5);"
                                     "m = sys.modules.setdefault('zope', types.ModuleType('zope'))\n"),
    ("easy-install.pth", "./some_egg.egg\n/abs/path\n"),
    ("anything.pth", "/just/a/path\n"),
])
def test_normal_hooks_pass(name, content):
    assert pth_verdict(name, content) == (None, "")


@pytest.mark.parametrize("name,content", [
    ("cook.pth", "import cook\n"),                                # litellm 1.107.0
    ("_virtualenv.pth", "import _virtualenv\nimport cook\n"),     # a known name with an extra line
    ("_virtualenv.pth", "import evil\n"),                         # a known name with other content
    ("__editable__.x.pth", "import os; os.system('id')\n"),
    ("zz-nspkg.pth", "import os\n"),
    ("evil.pth", "import _virtualenv\n"),                       # a known content under another name
])
def test_other_import_lines_are_high(name, content):
    assert pth_verdict(name, content)[0] == "high"


def test_risky_code_says_so():
    sev, reason = pth_verdict("x.pth", "import base64,os;exec(base64.b64decode('aWQ='))\n")
    assert sev == "high" and "exec" in reason


def test_import_must_start_the_line():
    assert pth_verdict("x.pth", "  import cook\n#import cook\n") == (None, "")


def test_one_walk_finds_both_kinds_inside_site_packages_only(tmp_path):
    site = tmp_path / "proj" / ".venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "cook.pth").write_text("import cook\n")
    (site / "sitecustomize.py").write_text("print('hi')\n")
    (tmp_path / "proj" / "sitecustomize.py").write_text("not in site-packages\n")
    (tmp_path / "proj" / "loose.pth").write_text("import x\n")
    nm = tmp_path / "web" / "node_modules" / "site-packages"
    nm.mkdir(parents=True)
    (nm / "ignored.pth").write_text("import x\n")
    pths, customizes = _startup_files(tmp_path)
    assert [p.name for p in pths] == ["cook.pth"]
    assert [p.name for p in customizes] == ["sitecustomize.py"]


def test_the_persistence_check_reports_them(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(scanner, "_home", lambda: tmp_path)
    site = tmp_path / ".local" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "cook.pth").write_text("import cook\n")
    (site / "_virtualenv.pth").write_text("import _virtualenv\n")
    (site / "usercustomize.py").write_text("x = 1\n")
    found = [(f.severity, f.title) for f in scanner.check_persistence() if "startup" in f.title.lower()]
    assert found == [("high", "Python startup file runs code: cook.pth"),
                     ("high", "Python startup file: %s" % (site / "usercustomize.py"))]
