#!/usr/bin/env python3
"""
Feature contract drift checker for webgates workspace.

This script validates that:
1. The features documented in `webgates/FEATURE_MATRIX.md` match the
   actual crate `Cargo.toml` feature declarations (auto-discovered from the workspace).
2. No undocumented features exist in `Cargo.toml` files (for non-example crates).
3. Optionally test minimal feature combinations listed in the markdown (unless --check-only).

Usage:
    ./scripts/check_feature_contract.py [--check-only]

    --check-only: Only check documentation/code drift, skip compilation tests
"""

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

# toml parsing: prefer stdlib tomllib (py3.11+), fall back to toml package
try:
    import tomllib

    def toml_load(path: Path) -> Dict:
        with open(path, "rb") as f:
            return tomllib.load(f)
except ModuleNotFoundError:
    import toml

    def toml_load(path: Path) -> Dict:
        with open(path, "r") as f:
            return toml.load(f)


REPO_ROOT = Path(__file__).parent.parent.resolve()
FEATURE_MATRIX_MD = REPO_ROOT / "FEATURE_MATRIX.md"
WORKSPACE_CARGO = REPO_ROOT / "Cargo.toml"


def discover_workspace_members() -> List[Path]:
    """Discover workspace member directories from the top-level Cargo.toml.

    This expands simple globs if present and returns a list of Path objects.
    """
    if not WORKSPACE_CARGO.exists():
        raise FileNotFoundError(f"Workspace Cargo.toml not found at {WORKSPACE_CARGO}")

    data = toml_load(WORKSPACE_CARGO)
    members = data.get("workspace", {}).get("members", [])

    resolved: List[Path] = []
    for m in members:
        # support simple glob patterns
        if any(ch in m for ch in "*?[]"):
            for p in REPO_ROOT.glob(m):
                if p.exists():
                    resolved.append(p)
        else:
            p = REPO_ROOT / m
            if p.exists():
                resolved.append(p)
    return resolved


def is_example_path(path: Path) -> bool:
    """Return True if the path lives under an examples/ directory (skip these)."""
    return "examples" in [part.lower() for part in path.parts]


def discover_crates() -> Dict[str, Dict]:
    """Return a map of package name -> {path: Path, features: dict} for workspace crates.

    Skips crates that appear under `examples/`.
    """
    crates: Dict[str, Dict] = {}
    members = discover_workspace_members()

    for member in members:
        # skip example crates (they are not part of the canonical feature matrix)
        if is_example_path(member):
            continue

        cargo_toml = member / "Cargo.toml"
        if not cargo_toml.exists():
            continue

        try:
            data = toml_load(cargo_toml)
        except Exception as e:
            print(f"Warning: failed to load {cargo_toml}: {e}")
            continue

        pkg = data.get("package")
        if not pkg:
            # workspace member without a package
            continue

        name = pkg.get("name")
        features = data.get("features", {}) or {}

        crates[name] = {"path": member, "features": features}

    return crates


def parse_feature_matrix_md(path: Path) -> Dict[str, Dict]:
    """Parse the FEATURE_MATRIX.md file and return a dict mapping crate -> {features, minimal_combinations}.

    This parser is intentionally conservative: it looks for '### <crate>' headings,
    a '**Features:**' section with bulleted lines containing a code span like
    `name = [..]`, and a '**Minimal combinations that must compile:**' section
    with bulleted command lines.
    """
    if not path.exists():
        raise FileNotFoundError(f"FEATURE_MATRIX.md not found at {path}")

    text = path.read_text()
    lines = text.splitlines()

    doc: Dict[str, Dict] = {}
    current: str | None = None
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()
        m = re.match(r"^\s*###\s+(.+)$", line)
        if m:
            current = m.group(1).strip()
            # initialize crate entry
            doc[current] = {"features": {}, "minimal_combinations": []}
            i += 1
            continue

        if not current:
            i += 1
            continue

        # Features block
        if re.search(r"\*\*Features:\*\*", line):
            i += 1
            while i < len(lines):
                l = lines[i].strip()
                if (
                    not l
                    or l.startswith("**Minimal")
                    or re.match(r"^\s*###\s+", lines[i])
                    or re.match(r"^\s*##\s+", lines[i])
                ):
                    break

                if l.startswith("-"):
                    # capture code inside backticks if available, otherwise the rest of the line
                    m2 = re.search(r"`([^`]+)`", l)
                    code = m2.group(1).strip() if m2 else l.lstrip("-").strip()

                    # parse "name = [..]" or simple "default = []"
                    if "=" in code:
                        name, rhs = code.split("=", 1)
                        name = name.strip()
                        rhs = rhs.strip()
                        deps: List[str] = []
                        if rhs.startswith("["):
                            try:
                                deps = list(ast.literal_eval(rhs))
                            except Exception:
                                # naive fallback
                                deps = [
                                    s.strip().strip("\"'")
                                    for s in re.split(r",\s*", rhs.strip("[] "))
                                    if s.strip()
                                ]
                        else:
                            deps = []
                    else:
                        name = code.strip()
                        deps = []

                    doc[current]["features"][name] = deps

                i += 1
            continue

        # Minimal combinations block
        if re.search(r"\*\*Minimal combinations", line):
            i += 1
            while i < len(lines):
                l = lines[i].strip()
                if (
                    not l
                    or re.match(r"^\s*###\s+", lines[i])
                    or re.match(r"^\s*##\s+", lines[i])
                ):
                    break

                if l.startswith("-"):
                    m2 = re.search(r"`([^`]+)`", l)
                    combo = m2.group(1) if m2 else l.lstrip("-").strip()
                    if combo.strip().lower() in ("(default only)", "(default)"):
                        combo = ""
                    doc[current]["minimal_combinations"].append(combo)

                i += 1
            continue

        i += 1

    return doc


def normalize_feature_deps(deps) -> List[str]:
    if not deps:
        return []
    if isinstance(deps, list):
        return sorted([str(d) for d in deps])
    return [str(deps)]


def run_cargo_command(crate_name: str, feature_args: str) -> bool:
    """Run `cargo check -p <crate>` with optional feature args (string)."""
    cmd = ["cargo", "check", "-p", crate_name]
    if feature_args and feature_args.strip():
        cmd.extend(feature_args.split())

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        if result.returncode != 0:
            print(f"\n--- cargo output for: {' '.join(cmd)} ---")
            print(result.stdout)
            print(result.stderr)
            print("--- end cargo output ---\n")
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command {' '.join(cmd)}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Check feature contract compliance")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only check documentation drift, skip compilation tests",
    )
    args = parser.parse_args()

    all_errors: List[str] = []

    print("🔍 Checking feature contract compliance...")

    crates = discover_crates()
    print(f"  ✅ Discovered {len(crates)} workspace crates (excluding examples)")

    try:
        doc_matrix = parse_feature_matrix_md(FEATURE_MATRIX_MD)
    except Exception as e:
        print(f"Error reading FEATURE_MATRIX.md: {e}")
        sys.exit(1)

    print(f"  🗒️  Parsed FEATURE_MATRIX.md with {len(doc_matrix)} documented crates")

    # Check for crates that exist but are not documented
    for crate_name, info in sorted(crates.items()):
        if crate_name not in doc_matrix:
            all_errors.append(
                f"{crate_name}: Crate present in workspace but missing from FEATURE_MATRIX.md"
            )

    # Check for documented crates that don't exist
    for doc_crate in sorted(doc_matrix.keys()):
        if doc_crate not in crates:
            all_errors.append(
                f"{doc_crate}: Documented in FEATURE_MATRIX.md but no matching crate found in workspace"
            )

    # For crates that are both documented and exist, compare feature sets
    for crate_name in sorted(crates.keys()):
        if crate_name not in doc_matrix:
            continue

        cargo_features = crates[crate_name]["features"]
        doc_features = doc_matrix[crate_name]["features"]

        # Check for missing/changed features
        for feat, expected_deps in doc_features.items():
            if feat not in cargo_features:
                all_errors.append(
                    f"{crate_name}: Missing feature '{feat}' in Cargo.toml"
                )
            else:
                actual_deps = normalize_feature_deps(cargo_features.get(feat, []))
                expected_deps_sorted = normalize_feature_deps(expected_deps)
                if actual_deps != expected_deps_sorted:
                    all_errors.append(
                        f"{crate_name}: Feature '{feat}' has different dependencies. Expected: {expected_deps_sorted}, Actual: {actual_deps}"
                    )

        # Check for undocumented features present in Cargo.toml
        for feat in cargo_features:
            if feat not in doc_features:
                all_errors.append(
                    f"{crate_name}: Undocumented feature '{feat}' found in Cargo.toml"
                )

    # Optionally run minimal combination compile checks
    if not args.check_only:
        print("⚙️  Testing minimal feature combinations (this may take a while)...")
        for doc_crate, info in sorted(doc_matrix.items()):
            if doc_crate not in crates:
                # already reported above
                continue

            combos = info.get("minimal_combinations") or [""]
            print(f"  🔨 Testing {doc_crate} ({len(combos)} combinations)")
            for combo in combos:
                combo_desc = combo if combo else "(default features)"
                ok = run_cargo_command(doc_crate, combo)
                if not ok:
                    all_errors.append(
                        f"{doc_crate}: Minimal combination '{combo_desc}' failed to compile"
                    )

    # Report results
    if all_errors:
        print("\n❌ Feature contract validation failed:")
        for error in all_errors:
            print(f"  • {error}")
        sys.exit(1)

    print("\n✅ Feature contract validation passed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
