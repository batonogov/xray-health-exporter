#!/usr/bin/env python3
"""Validate dashboard structure and export its queries for promtool validation."""

import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-rules", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    dashboard = json.loads((root / "grafana/dashboard.json").read_text())
    names = [variable["name"] for variable in dashboard["templating"]["list"]]
    if len(names) != len(set(names)):
        raise ValueError("duplicate dashboard variable")
    panels = dashboard["panels"]
    ids = [panel["id"] for panel in panels if "id" in panel]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate panel ID")
    rules = []
    rectangles = []
    for panel in panels:
        box = panel["gridPos"]
        x, y, width, height = (box[key] for key in ("x", "y", "w", "h"))
        if min(x, y) < 0 or min(width, height) <= 0 or x + width > 24:
            raise ValueError(f"invalid panel bounds: {panel['title']}")
        for px, py, pw, ph in rectangles:
            if x < px + pw and px < x + width and y < py + ph and py < y + height:
                raise ValueError(f"overlapping panel: {panel['title']}")
        rectangles.append((x, y, width, height))
        for target in panel.get("targets", []):
            expression = target.get("expr")
            if not expression:
                continue
            expression = expression.replace("$__rate_interval", "5m").replace("$__range", "1h")
            for name in sorted(names, key=len, reverse=True):
                expression = expression.replace("${" + name + "}", ".*").replace("$" + name, ".*")
            if re.search(r"\$[A-Za-z_{]", expression):
                raise ValueError(f"unresolved query variable: {expression}")
            rules.append({"record": f"xray_dashboard_validation_{len(rules)}", "expr": expression})
    args.output_rules.write_text(json.dumps({"groups": [{"name": "dashboard-validation", "rules": rules}]}, indent=2) + "\n")
    print(f"Validated {len(panels)} panels; exported {len(rules)} PromQL queries")


if __name__ == "__main__":
    main()
