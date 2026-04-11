#!/usr/bin/env python3
"""Render a companion module template with values from companions.yaml.

Usage:
    companion-render-template.py [--dest] <template-file> <module-name>

Reads companions.yaml and .companions/templates.yaml from the repository
root, checks scope rules, substitutes placeholders, and writes the result
to stdout.

Flags:
    --dest  Print the destination path instead of rendering the template.

Placeholders:
    {{name}}   — module name (e.g. "ed448")
    {{branch}} — default branch from companions.yaml (e.g. "develop/v4")

Scope rules (from .companions/templates.yaml):
    skip: [list]  — template applies to all modules except listed
    only: [list]  — template applies only to listed modules
    (neither)     — template applies to all modules

If a template is skipped for a module, exits 0 with no stdout output
and prints a SKIP message to stderr.
"""

import os
import sys
import yaml


def find_root():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(script_dir)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def find_module(data, name):
    for m in data.get("modules", []):
        if m["name"] == name:
            return m
    return None


def check_scope(template_meta, module_name):
    """Return True if the template applies to this module."""
    skip = template_meta.get("skip")
    only = template_meta.get("only")
    if skip and module_name in skip:
        return False
    if only and module_name not in only:
        return False
    return True


def main():
    args = sys.argv[1:]
    dest_mode = False

    if args and args[0] == "--dest":
        dest_mode = True
        args = args[1:]

    if len(args) != 2:
        print(f"Usage: {sys.argv[0]} [--dest] <template-file> <module-name>", file=sys.stderr)
        sys.exit(1)

    template_file = args[0]
    module_name = args[1]
    template_basename = os.path.basename(template_file)

    root = find_root()
    companions = load_yaml(os.path.join(root, "companions.yaml"))
    manifest = load_yaml(os.path.join(root, ".companions", "templates.yaml"))

    module = find_module(companions, module_name)
    if module is None:
        print(f"ERROR: module '{module_name}' not found in companions.yaml", file=sys.stderr)
        sys.exit(1)

    template_meta = manifest.get("templates", {}).get(template_basename)
    if template_meta is None:
        print(f"ERROR: template '{template_basename}' not found in templates.yaml", file=sys.stderr)
        sys.exit(1)

    if not check_scope(template_meta, module_name):
        print(f"SKIP: template '{template_basename}' skipped for '{module_name}'", file=sys.stderr)
        sys.exit(0)

    if dest_mode:
        sys.stdout.write(template_meta["dest"] + "\n")
        return

    with open(template_file) as f:
        content = f.read()

    content = content.replace("{{name}}", module["name"])
    content = content.replace("{{branch}}", module.get("branch", "main"))

    sys.stdout.write(content)


if __name__ == "__main__":
    main()
