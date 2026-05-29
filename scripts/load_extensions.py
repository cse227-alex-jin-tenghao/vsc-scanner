"""One-shot loader: populate `main` (83793 rows) and `manager` (838 rows).

Reads the deduped marketplace JSON and uses COPY for `main` (fast bulk
insert), regular INSERT for the 838 manager rows. Idempotent for the
manager table; `main` uses ON CONFLICT DO NOTHING so a partial re-run
doesn't duplicate-fail on the UNIQUE(extension_id) constraint.

Idx assignment is the row's position in the (already-deduped) JSON file —
that's the contract nodes rely on for idx ↔ extension lookups.
"""

import json
import os
import sys
from pathlib import Path

import psycopg

JSON_PATH = Path("/home/alex/cse227/project/stuff/marketplace_extensions.json")
GROUP_SIZE = 100
PW_PATH = Path(__file__).resolve().parents[1] / "pw.txt"

CONN_STR = (
    "postgresql://postgres.lnoxdusiuktldwelqakn"
    "@aws-1-us-west-1.pooler.supabase.com:5432/postgres"
)


def extension_id(entry: dict) -> str:
    return f"{entry['publisher']['publisherName']}.{entry['extensionName']}"


def main() -> None:
    extensions = json.loads(JSON_PATH.read_text())
    n = len(extensions)
    groups = (n + GROUP_SIZE - 1) // GROUP_SIZE
    last_group_size = n - (groups - 1) * GROUP_SIZE
    print(f"loaded {n} extensions; {groups} groups ({groups-1} full + last={last_group_size})")

    password = PW_PATH.read_text().strip()
    with psycopg.connect(CONN_STR, password=password, autocommit=False) as conn:
        with conn.cursor() as cur:
            # Bail if `main` already has rows — loader is one-shot. To
            # re-run intentionally, TRUNCATE the tables first.
            cur.execute("SELECT COUNT(*) FROM main")
            existing = cur.fetchone()[0]
            if existing:
                print(f"refusing to load: main already has {existing} rows", file=sys.stderr)
                sys.exit(1)

            print("COPYing into main...")
            with cur.copy("COPY main (idx, extension_id) FROM STDIN") as copy:
                for idx, ext in enumerate(extensions):
                    copy.write_row((idx, extension_id(ext)))

            print(f"inserting {groups} manager rows...")
            cur.executemany(
                "INSERT INTO manager (group_idx) VALUES (%s)",
                [(g,) for g in range(groups)],
            )

        conn.commit()

    print("done.")


if __name__ == "__main__":
    main()
