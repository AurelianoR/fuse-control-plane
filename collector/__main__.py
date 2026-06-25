import argparse
import os
import sys

from collector.graph.activity import fetch_activity
from collector.graph.client import GraphClient
from collector.graph.grants import fetch_grants
from collector.output.report import print_report
from collector.snapshot.store import SnapshotStore


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fuse: enumerate and track OAuth grants in an Azure tenant"
    )
    parser.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.environ.get("AZURE_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.environ.get("AZURE_CLIENT_SECRET"))
    parser.add_argument("--snapshot-dir", default="./snapshots")
    parser.add_argument("--output", choices=["table", "json"], default="table")
    parser.add_argument(
        "--include-activity",
        action="store_true",
        help="Fetch last-used timestamps via servicePrincipalSignInActivities (requires Entra P1/P2)",
    )
    args = parser.parse_args()

    missing = [
        label
        for label, val in [
            ("AZURE_TENANT_ID / --tenant-id", args.tenant_id),
            ("AZURE_CLIENT_ID / --client-id", args.client_id),
            ("AZURE_CLIENT_SECRET / --client-secret", args.client_secret),
        ]
        if not val
    ]
    if missing:
        print(f"Error: missing required: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    client = GraphClient(args.tenant_id, args.client_id, args.client_secret)
    store = SnapshotStore(args.snapshot_dir)

    grants = fetch_grants(client, args.tenant_id)

    if args.include_activity:
        activity_by_app_id = fetch_activity(client)
        for g in grants:
            g.activity = activity_by_app_id.get(g.client_app_id)

    previous = store.load_latest()
    if previous:
        grants = store.merge_first_seen(previous, grants)

    diff = store.diff(previous, grants) if previous else None
    store.save(grants)

    print_report(grants, diff, output_format=args.output)


if __name__ == "__main__":
    main()
