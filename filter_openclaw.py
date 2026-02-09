#!/usr/bin/env python3
"""Filter skills.json to only include skills authored by 'openclaw'."""

import json


def main():
    input_file = "skills.json"
    output_file = "openclaw_skills.json"

    with open(input_file, "r", encoding="utf-8") as f:
        skills = json.load(f)

    openclaw_skills = [s for s in skills if s.get("author") == "openclaw"]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(openclaw_skills, f, indent=2, ensure_ascii=False)

    print(f"Filtered {len(openclaw_skills)} openclaw skills out of {len(skills)} total.")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    main()
