#!/usr/bin/env python3
"""Apply repository settings and rulesets to companion modules.

Usage:
    companion-apply-settings.py [--dry-run] [--modules=name,name,...]

Reads companions.yaml for the module list and .companions/settings.yaml
for the desired settings. Applies:
  1. Repository settings via gh repo edit (merge strategies, wiki, etc.)
  2. Repository rulesets via GitHub API (branch protection rules)

Flags:
    --dry-run              Print commands without executing them.
    --modules=name,name    Target only the listed modules.
"""

import json
import os
import subprocess
import sys
import tempfile
import yaml


def find_root():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(script_dir)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def repo_slug(module):
    """Extract owner/repo from git URL."""
    url = module["repo"]
    if url.startswith("git@github.com:"):
        slug = url[len("git@github.com:"):]
    elif url.startswith("https://github.com/"):
        slug = url[len("https://github.com/"):]
    else:
        return None
    return slug.removesuffix(".git")


def build_flags(settings):
    """Convert settings dict to gh repo edit flags."""
    flags = []
    for key, value in sorted(settings.items()):
        if isinstance(value, bool):
            if value:
                flags.append(f"--{key}")
            else:
                flags.append(f"--{key}=false")
        else:
            flags.append(f"--{key}={value}")
    return flags


def render_ruleset(ruleset_template, module):
    """Deep-copy a ruleset template and substitute placeholders.

    Strips meta fields (skip, only) that control applicability but are not
    part of the GitHub ruleset schema.
    """
    stripped = {k: v for k, v in ruleset_template.items() if k not in ("skip", "only")}
    raw = json.dumps(stripped)
    raw = raw.replace("{{name}}", module["name"])
    raw = raw.replace("{{branch}}", module.get("branch", "main"))
    return json.loads(raw)


def ruleset_applies(ruleset_template, module_name):
    """Check scope rules. Returns True if the ruleset applies to this module."""
    skip = ruleset_template.get("skip")
    only = ruleset_template.get("only")
    if skip and only:
        raise ValueError(f"ruleset '{ruleset_template.get('name')}' has both skip and only")
    if skip is not None and module_name in skip:
        return False
    if only is not None and module_name not in only:
        return False
    return True


def get_existing_rulesets(slug):
    """Fetch existing rulesets for a repo, return {name: id} map."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{slug}/rulesets"],
            check=True, capture_output=True, text=True,
        )
        rulesets = json.loads(result.stdout)
        return {rs["name"]: rs["id"] for rs in rulesets}
    except subprocess.CalledProcessError:
        return {}


def apply_ruleset(slug, ruleset, existing_ids, dry_run):
    """Create or update a ruleset. Returns (status, note)."""
    name = ruleset["name"]
    existing_id = existing_ids.get(name)

    if existing_id:
        method = "PUT"
        endpoint = f"repos/{slug}/rulesets/{existing_id}"
        action = "update"
    else:
        method = "POST"
        endpoint = f"repos/{slug}/rulesets"
        action = "create"

    if dry_run:
        print(f"  gh api --method {method} {endpoint} (ruleset: {name})")
        return "DRY-RUN", f"{action} ruleset '{name}'"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(ruleset, f)
        tmppath = f.name

    try:
        subprocess.run(
            ["gh", "api", "--method", method, endpoint, "--input", tmppath],
            check=True, capture_output=True, text=True,
        )
        return "OK", f"{action} ruleset '{name}'"
    except subprocess.CalledProcessError as e:
        return "FAILED", e.stderr.strip()
    finally:
        os.unlink(tmppath)


def apply_repo_settings(slug, settings, dry_run):
    """Apply gh repo edit settings. Returns (status, note)."""
    flags = build_flags(settings)
    cmd = ["gh", "repo", "edit", slug] + flags

    if dry_run:
        print(f"  {' '.join(cmd)}")
        return "DRY-RUN", ""

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return "OK", ""
    except subprocess.CalledProcessError as e:
        return "FAILED", e.stderr.strip()


def main():
    args = sys.argv[1:]
    dry_run = False
    filter_modules = None

    remaining = []
    for arg in args:
        if arg == "--dry-run":
            dry_run = True
        elif arg.startswith("--modules="):
            filter_modules = set(arg[len("--modules="):].split(","))
        else:
            remaining.append(arg)

    if remaining:
        print(f"Usage: {sys.argv[0]} [--dry-run] [--modules=name,name,...]", file=sys.stderr)
        sys.exit(1)

    root = find_root()
    companions = load_yaml(os.path.join(root, "companions.yaml"))
    settings = load_yaml(os.path.join(root, ".companions", "settings.yaml"))

    defaults = settings.get("defaults", {})
    overrides = settings.get("overrides", {})
    ruleset_templates = settings.get("rulesets", [])

    modules = companions.get("modules", [])
    if filter_modules:
        modules = [m for m in modules if m["name"] in filter_modules]
        found = {m["name"] for m in modules}
        missing = filter_modules - found
        if missing:
            print(f"ERROR: modules not found in companions.yaml: {', '.join(sorted(missing))}", file=sys.stderr)
            sys.exit(1)

    results = []

    for module in modules:
        name = module["name"]
        slug = repo_slug(module)
        if slug is None:
            results.append((name, "SKIP", "unrecognized repo URL"))
            continue

        # Repo settings
        merged = dict(defaults)
        if name in overrides:
            merged.update(overrides[name])

        status, note = apply_repo_settings(slug, merged, dry_run)
        results.append((name, status, note if note else "repo settings"))

        # Rulesets
        if ruleset_templates:
            existing = {} if dry_run else get_existing_rulesets(slug)
            for tmpl in ruleset_templates:
                if not ruleset_applies(tmpl, name):
                    results.append((name, "SKIP", f"ruleset '{tmpl.get('name')}' out of scope"))
                    continue
                rendered = render_ruleset(tmpl, module)
                status, note = apply_ruleset(slug, rendered, existing, dry_run)
                results.append((name, status, note))

    print()
    print(f"{'Module':<15} {'Status':<10} {'Notes'}")
    print(f"{'-'*15} {'-'*10} {'-'*40}")
    for name, status, notes in results:
        print(f"{name:<15} {status:<10} {notes}")


if __name__ == "__main__":
    main()
