from pathlib import Path
from usetlint import parse_update_set

FIX = Path(__file__).parent / "fixtures"


def test_parse_counts_and_fields():
    changes = parse_update_set((FIX / "set_a.xml").read_text())
    assert len(changes) == 3
    br = changes[0]
    assert br.type == "Business Rule" and br.target == "incident"
    assert br.table == "sys_script"
    assert "current.update" in br.payload
