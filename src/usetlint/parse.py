"""Parse an exported Update Set (unload XML) into a list of Changes.

ServiceNow exports look like:
  <unload>
    <sys_update_xml action="INSERT_OR_UPDATE">
      <name>sys_script_abc123</name>
      <type>Business Rule</type>
      <target_name>incident</target_name>
      <update_set>...</update_set>
      <payload>... &lt;record&gt; ...</payload>
    </sys_update_xml>
  </unload>
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List


@dataclass
class Change:
    name: str            # e.g. sys_script_abc123
    type: str            # e.g. "Business Rule"
    target: str          # e.g. "incident" or record display name
    action: str          # INSERT_OR_UPDATE / DELETE
    payload: str = ""    # inner record XML (text)

    @property
    def table(self) -> str:
        # sys_update_xml name is usually <table>_<sysid>
        return self.name.rsplit("_", 1)[0] if "_" in self.name else self.name


def _text(node, tag: str) -> str:
    el = node.find(tag)
    return (el.text or "").strip() if el is not None else ""


def parse_update_set(xml_text: str) -> List[Change]:
    root = ET.fromstring(xml_text)
    changes: List[Change] = []
    for upd in root.iter("sys_update_xml"):
        changes.append(Change(
            name=_text(upd, "name"),
            type=_text(upd, "type"),
            target=_text(upd, "target_name"),
            action=upd.get("action", _text(upd, "action") or "INSERT_OR_UPDATE"),
            payload=_text(upd, "payload"),
        ))
    return changes
