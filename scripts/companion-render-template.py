#!/usr/bin/env python3
"""Render a companion module template with values from companions.yaml.

Usage:
    companion-render-template.py <template-file> <module-name>

Reads companions.yaml from the repository root, substitutes placeholders
in the template, and writes the result to stdout.

Placeholders:
    {{name}}   — module name (e.g. "ed448")
    {{branch}} — default branch from companions.yaml (e.g. "develop/v4")
"""

import os
import sys
import yaml


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <template-file> <module-name>", file=sys.stderr)
        sys.exit(1)

    template_file = sys.argv[1]
    module_name = sys.argv[2]

    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    companions_yaml = os.path.join(root, "companions.yaml")

    with open(companions_yaml) as f:
        data = yaml.safe_load(f)

    module = None
    for m in data.get("modules", []):
        if m["name"] == module_name:
            module = m
            break

    if module is None:
        print(f"ERROR: module '{module_name}' not found in companions.yaml", file=sys.stderr)
        sys.exit(1)

    with open(template_file) as f:
        content = f.read()

    content = content.replace("{{name}}", module["name"])
    content = content.replace("{{branch}}", module.get("branch", "main"))

    sys.stdout.write(content)


if __name__ == "__main__":
    main()
