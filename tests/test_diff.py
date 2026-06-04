from pathlib import Path
from usetlint import parse_update_set, diff_update_sets

FIX = Path(__file__).parent / "fixtures"


def test_diff_added_removed_changed():
    a = parse_update_set((FIX / "set_a.xml").read_text())
    b = parse_update_set((FIX / "set_b.xml").read_text())
    d = diff_update_sets(a, b)
    assert "sys_script_ddd444" in d["added"]
    assert "sys_security_acl_bbb222" in d["removed"]
    assert "sys_script_aaa111" in d["changed"]   # payload edited
