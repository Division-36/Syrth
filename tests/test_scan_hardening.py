"""Trust boundaries when the scanner is pointed at untrusted source."""

from __future__ import annotations

import sys
from pathlib import Path

from test_patch_and_benchmarks import RCE, first_finding

import syrth.scan as scan_module
from syrth.patch import CommandBackend
from syrth.scan import SyrthScanner


def test_oversized_file_is_reported_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(scan_module, "MAX_FILE_BYTES", 8)
    target = tmp_path / "huge.py"
    target.write_text("def f(): pass\n", encoding="utf-8")
    report = SyrthScanner().scan_file(str(target))
    assert report.errors
    assert "exceeds 8 bytes" in report.errors[0][1]


def test_patch_command_uses_a_private_temp_dir(tmp_path: Path):
    seen = tmp_path / "arg.txt"
    script = tmp_path / "record.py"
    script.write_text(
        f"import pathlib, sys\npathlib.Path({str(seen)!r}).write_text(sys.argv[1])\n"
        "sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())\n",
        encoding="utf-8",
    )
    backend = CommandBackend([sys.executable, str(script)], name="test")
    scanner = SyrthScanner()
    report, finding = first_finding(RCE, scanner)
    backend.propose(RCE, finding, report.traces[0])

    target = Path(seen.read_text(encoding="utf-8"))
    assert target.name == "input.py"
    assert target.parent.parent != Path.cwd()
    assert not target.exists()
    assert not Path(".syrth-patch").exists()
