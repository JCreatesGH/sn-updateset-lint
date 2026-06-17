import json
from pathlib import Path

from usetlint.cli import main

FIX = Path(__file__).parent / "fixtures"
A = str(FIX / "set_a.xml")
B = str(FIX / "set_b.xml")


def test_lint_json_and_high_exit(capsys):
    assert main([A]) == 1                         # set_a has HIGH findings -> fail
    capsys.readouterr()
    assert main([A, "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["changes"] == 3
    assert any(f["severity"] == "high" for f in out["findings"])


def test_fail_on_none_and_min_severity(capsys):
    assert main([A, "--fail-on", "none"]) == 0    # never fail
    capsys.readouterr()
    # min-severity high hides lower findings from the printed list
    main([A, "--min-severity", "high"])
    out = capsys.readouterr().out
    assert "[HIGH" in out and "[MEDIUM" not in out


def test_diff_mode_json(capsys):
    code = main([A, B, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert "sys_script_ddd444" in out["diff"]["added"]
    assert "sys_security_acl_bbb222" in out["diff"]["removed"]
    # diff gates on risk newly introduced by added/changed entries
    assert code in (0, 1)


def test_bad_xml_returns_2(capsys):
    bad = FIX / "broken.xml"
    bad.write_text("<unload><sys_update_xml>")     # truncated / malformed
    try:
        assert main([str(bad)]) == 2
        assert "usetlint:" in capsys.readouterr().err
    finally:
        bad.unlink()


def test_missing_file_returns_2(capsys):
    assert main(["/no/such/file.xml"]) == 2
    assert "usetlint:" in capsys.readouterr().err


def test_too_many_files_returns_2(capsys):
    assert main([A, B, A]) == 2
