"""Minimal product client: it talks only to the local Agent API."""

import argparse
from bke_licensing_agent.local_api import request_authorization


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-url", required=True)
    parser.add_argument("--product-id", default="agent-demo-product")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--installation-id", required=True)
    args = parser.parse_args()
    result = request_authorization(args.agent_url, args.product_id, args.version, args.installation_id)
    print("ALLOW" if result["authorized"] else "DENY")
    return 0 if result["authorized"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
