#!/usr/bin/env python3
"""
Feature contract drift checker for webgates workspace.

This script validates that:
1. All features documented in FEATURE_MATRIX.md exist in Cargo.toml files
2. No undocumented features exist in Cargo.toml files 
3. All minimal feature combinations compile successfully

Usage:
    ./scripts/check_feature_contract.py [--check-only]
    
    --check-only: Only check documentation/code drift, skip compilation tests
"""

import subprocess
import sys
import re
import toml
import argparse
from pathlib import Path
from typing import Dict, List, Set, Optional

# Workspace root
REPO_ROOT = Path(__file__).parent.parent

# Expected feature matrix from FEATURE_MATRIX.md
FEATURE_MATRIX = {
    "webgates": {
        "features": {
            "default": [],
            "wasm": ["uuid/js"],
            "codecs": ["dep:chrono", "dep:serde_json", "dep:serde_with", "dep:webgates-codecs"],
            "secrets": ["dep:rand", "dep:webgates-secrets"],
            "repositories": ["dep:webgates-repositories"],
            "sessions": ["codecs", "repositories", "secrets", "dep:webgates-sessions"],
            "cookies": ["codecs", "dep:cookie"],
            "oauth2": ["codecs", "cookies", "repositories", "dep:oauth2"],
            "authn": ["codecs", "repositories", "secrets", "tokio/rt-multi-thread", "dep:tracing"],
            "audit-logging": ["dep:tracing"],
            "prometheus": ["audit-logging", "dep:prometheus"],
            "full": ["authn", "audit-logging", "codecs", "cookies", "oauth2", "prometheus", "repositories", "secrets", "sessions"]
        },
        "minimal_combinations": [
            "--no-default-features --features codecs",
            "--no-default-features --features cookies", 
            "--no-default-features --features oauth2",
            "--no-default-features --features authn",
            "--features wasm",
            "--features full"
        ]
    },
    "webgates-core": {
        "features": {"default": []},
        "minimal_combinations": [""]
    },
    "webgates-axum": {
        "features": {"default": []},
        "minimal_combinations": ["", "--all-features"]
    },
    "webgates-repositories": {
        "features": {
            "default": [],
            "audit-logging": ["dep:tracing"],
            "surrealdb": ["dep:surrealdb"],
            "sea-orm": ["dep:sea-orm"]
        },
        "minimal_combinations": [
            "",
            "--features surrealdb",
            "--features sea-orm", 
            "--all-features"
        ]
    },
    "webgates-sessions": {
        "features": {"default": []},
        "minimal_combinations": [""]
    },
    "webgates-codecs": {
        "features": {"default": []},
        "minimal_combinations": [""]
    },
    "webgates-secrets": {
        "features": {"default": []},
        "minimal_combinations": [""]
    }
}

def load_cargo_toml(crate_name: str) -> Dict:
    """Load and parse Cargo.toml for the given crate."""
    cargo_path = REPO_ROOT / crate_name / "Cargo.toml"
    if not cargo_path.exists():
        raise FileNotFoundError(f"Cargo.toml not found for crate: {crate_name}")
    
    with open(cargo_path, 'r') as f:
        return toml.load(f)

def normalize_feature_deps(deps: List[str]) -> List[str]:
    """Normalize feature dependency lists for comparison."""
    return sorted(deps) if deps else []

def check_feature_drift(crate_name: str) -> List[str]:
    """Check if documented features match actual Cargo.toml features."""
    errors = []
    
    try:
        cargo_data = load_cargo_toml(crate_name)
        actual_features = cargo_data.get("features", {})
        expected_features = FEATURE_MATRIX[crate_name]["features"]
        
        # Check for missing features
        for feature, deps in expected_features.items():
            if feature not in actual_features:
                errors.append(f"{crate_name}: Missing feature '{feature}' in Cargo.toml")
            else:
                actual_deps = normalize_feature_deps(actual_features[feature])
                expected_deps = normalize_feature_deps(deps)
                if actual_deps != expected_deps:
                    errors.append(f"{crate_name}: Feature '{feature}' has different dependencies. Expected: {expected_deps}, Actual: {actual_deps}")
        
        # Check for undocumented features
        for feature in actual_features:
            if feature not in expected_features:
                errors.append(f"{crate_name}: Undocumented feature '{feature}' found in Cargo.toml")
                
    except Exception as e:
        errors.append(f"{crate_name}: Error loading Cargo.toml: {e}")
    
    return errors

def run_cargo_command(crate_name: str, feature_args: str) -> bool:
    """Run cargo check for a specific crate and feature combination."""
    cmd = ["cargo", "check", "-p", crate_name]
    if feature_args.strip():
        cmd.extend(feature_args.split())
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command {' '.join(cmd)}: {e}")
        return False

def check_minimal_combinations(crate_name: str) -> List[str]:
    """Check that all minimal feature combinations compile."""
    errors = []
    combinations = FEATURE_MATRIX[crate_name]["minimal_combinations"]
    
    for combo in combinations:
        combo_desc = combo if combo else "(default features)"
        if not run_cargo_command(crate_name, combo):
            errors.append(f"{crate_name}: Minimal combination '{combo_desc}' failed to compile")
    
    return errors

def main():
    parser = argparse.ArgumentParser(description="Check feature contract compliance")
    parser.add_argument("--check-only", action="store_true", 
                        help="Only check documentation drift, skip compilation tests")
    args = parser.parse_args()
    
    all_errors = []
    
    print("🔍 Checking feature contract compliance...")
    
    # Check feature drift for all crates
    for crate_name in FEATURE_MATRIX:
        print(f"  📦 Checking {crate_name} feature definitions...")
        errors = check_feature_drift(crate_name)
        all_errors.extend(errors)
    
    # Check minimal combinations compile (unless --check-only)
    if not args.check_only:
        print("⚙️  Testing minimal feature combinations...")
        for crate_name in FEATURE_MATRIX:
            print(f"  🔨 Testing {crate_name} minimal combinations...")
            errors = check_minimal_combinations(crate_name)
            all_errors.extend(errors)
    
    # Report results
    if all_errors:
        print("\n❌ Feature contract validation failed:")
        for error in all_errors:
            print(f"  • {error}")
        sys.exit(1)
    else:
        print("\n✅ Feature contract validation passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()