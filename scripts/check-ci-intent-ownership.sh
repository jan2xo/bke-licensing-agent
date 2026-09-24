#!/usr/bin/env bash
set -euo pipefail

mapfile -t pr_owners < <(grep -El '^[[:space:]]*pull_request:[[:space:]]*$' .github/workflows/*.yml | sort)
if [ "${#pr_owners[@]}" -ne 1 ] || [ "${pr_owners[0]}" != ".github/workflows/pr-guard.yml" ]; then
  printf 'CI intent ownership violation: automatic pull_request ownership must belong only to pr-guard.yml; found: %s\n' "${pr_owners[*]:-none}" >&2
  exit 1
fi

grep -q 'issue_comment:' .github/workflows/certify.yml
grep -q 'workflow_dispatch:' .github/workflows/certify.yml
grep -q 'required-certification:' .github/workflows/certify.yml
grep -q 'response.data.head.sha' .github/workflows/certify.yml
grep -q '_intent-contracts.yml' .github/workflows/certify.yml

grep -q 'push:' .github/workflows/ci.yml
grep -Fq 'branches: [main]' .github/workflows/ci.yml

for workflow in   ci.yml   dotnet-broken-update-rollback.yml   dotnet-desktop-ui.yml   dotnet-production-installer.yml   dotnet-production-release-preflight.yml   dotnet-production-signing.yml   dotnet-signed-self-update.yml   utm-disposable-target-trust.yml
do
  path=".github/workflows/$workflow"
  if grep -Eq '^[[:space:]]*pull_request:[[:space:]]*$' "$path"; then
    echo "CI intent ownership violation: $workflow must not auto-run on pull_request" >&2
    exit 1
  fi
done

for workflow in   dotnet-broken-update-rollback.yml   dotnet-desktop-ui.yml   dotnet-production-installer.yml   dotnet-production-release-preflight.yml   dotnet-production-signing.yml   dotnet-signed-self-update.yml   utm-disposable-target-trust.yml
do
  grep -q 'workflow_dispatch:' ".github/workflows/$workflow"
done

for path in .github/workflows/*.yml; do
  [ "$path" = ".github/workflows/pr-guard.yml" ] && continue
  if grep -q 'github.event.pull_request' "$path"; then
    echo "CI intent ownership violation: stale pull_request event context in $path" >&2
    exit 1
  fi
done

grep -q 'AUTHORIZE_PRODUCTION_SIGNING' .github/workflows/dotnet-production-signing.yml

echo 'Agent intent-driven CI ownership GREEN'
