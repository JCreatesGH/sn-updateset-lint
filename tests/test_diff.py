from pathlib import Path

from usetlint import parse_update_set, diff_update_sets, lint_diff
from usetlint.parse import Change

FIX = Path(__file__).parent / "fixtures"


def test_diff_added_removed_changed():
    a = parse_update_set((FIX / "set_a.xml").read_text())
    b = parse_update_set((FIX / "set_b.xml").read_text())
    d = diff_update_sets(a, b)
    assert "sys_script_ddd444" in d["added"]
    assert "sys_security_acl_bbb222" in d["removed"]
    assert "sys_script_aaa111" in d["changed"]   # payload edited


def test_diff_detects_action_or_target_change_not_just_payload():
    old = [Change("sys_script_x", "Business Rule", "incident", "INSERT_OR_UPDATE", "P")]
    # same payload, but action flipped to DELETE and retargeted
    new = [Change("sys_script_x", "Business Rule", "problem", "DELETE", "P")]
    d = diff_update_sets(old, new)
    assert d["changed"] == ["sys_script_x"]      # would have been missed by payload-only diff


def test_lint_diff_only_lints_added_and_changed():
    a = parse_update_set((FIX / "set_a.xml").read_text())
    b = parse_update_set((FIX / "set_b.xml").read_text())
    names = {f.change for f in lint_diff(a, b)}
    # ddd444 (added, setWorkflow) and aaa111 (changed) are in scope...
    assert "sys_script_ddd444" in names
    # ...bbb222 was REMOVED, so its risk is not re-flagged as newly introduced
    assert "sys_security_acl_bbb222" not in names
