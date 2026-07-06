"""
Org profile loader.

Reads an organization's profile (a small YAML file listing the
software/products they run) so the filtering module can match new KEV
entries against it. See docs/design.md for how this fits into the
overall pipeline.
"""

from pathlib import Path

import yaml


def load_org_profile(path: str = "data/org_profile.yaml") -> dict:
    """
    Load an organization profile from a YAML file.

    Returns a dict with keys:
        - organization_name: str
        - products: set of lowercased product/software names, for
          case insensitive matching against KEV entries

    Raises FileNotFoundError if the profile doesn't exist yet, callers
    should catch this and prompt for profile setup rather than crash.
    """
    profile_path = Path(path)

    if not profile_path.exists():
        raise FileNotFoundError(
            f"No org profile found at {path}. Copy "
            "data/org_profile.example.yaml to that path and fill in "
            "the organization's actual products first."
        )

    with open(profile_path, "r") as f:
        raw = yaml.safe_load(f)

    return {
        "organization_name": raw.get("organization_name", "Unknown"),
        "products": {p.lower().strip() for p in raw.get("products", [])},
    }


if __name__ == "__main__":
    profile = load_org_profile()
    print(f"Loaded profile for: {profile['organization_name']}")
    print(f"Tracking {len(profile['products'])} products:")
    for product in sorted(profile["products"]):
        print(f"- {product}")
