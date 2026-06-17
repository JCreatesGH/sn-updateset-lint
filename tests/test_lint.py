from pathlib import Path
from usetlint import parse_update_set, lint

FIX = Path(__file__).parent / "fixtures"


def rules(findings):
    return {f.rule for f in findings}


def test_flags_acl_global_br_eval_and_hardcoded():
    findings = lint(parse_update_set((FIX / "set_a.xml").read_text()))
    r = rules(findings)
    assert "acl-change" in r
    assert "global-business-rule" in r           # ccc333 has empty target
    assert "dynamic-eval" in r
    assert "hardcoded-reference" in r


def test_high_findings_sorted_first():
    findings = lint(parse_update_set((FIX / "set_a.xml").read_text()))
    assert findings[0].severity == "high"


def test_delete_and_setworkflow_flagged():
    findings = lint(parse_update_set((FIX / "set_b.xml").read_text()))
    r = rules(findings)
    assert "record-delete" in r
    assert "setworkflow-false" in r


def test_clean_set_has_no_high():
    xml = '<unload><sys_update_xml action="INSERT_OR_UPDATE"><name>sys_ui_policy_x</name><type>UI Policy</type><target_name>incident</target_name><payload>&lt;record&gt;ok&lt;/record&gt;</payload></sys_update_xml></unload>'
    findings = lint(parse_update_set(xml))
    assert all(f.severity != "high" for f in findings)


def test_current_update_in_br_is_flagged():
    # aaa111 in set_a is a Business Rule whose payload calls current.update()
    findings = lint(parse_update_set((FIX / "set_a.xml").read_text()))
    hits = [f for f in findings if f.rule == "current-update-in-br"]
    assert hits and hits[0].change == "sys_script_aaa111"


def test_scheduled_job_flagged():
    xml = ('<unload><sys_update_xml action="INSERT_OR_UPDATE"><name>sysauto_script_z</name>'
           '<type>Scheduled Script Execution</type><target_name>nightly</target_name>'
           '<payload>&lt;record&gt;x&lt;/record&gt;</payload></sys_update_xml></unload>')
    assert "scheduled-job" in rules(lint(parse_update_set(xml)))


def test_debug_logging_is_info_only():
    xml = ('<unload><sys_update_xml action="INSERT_OR_UPDATE"><name>sys_script_q</name>'
           '<type>Script Include</type><target_name>Utils</target_name>'
           '<payload>&lt;record&gt;console.log("hi");&lt;/record&gt;</payload></sys_update_xml></unload>')
    findings = lint(parse_update_set(xml))
    assert "debug-logging" in rules(findings)
    assert all(f.severity != "high" for f in findings)
