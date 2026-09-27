#!/usr/bin/env bash
set -euo pipefail

mapfile -t pr_owners < <(grep -El '^[[:space:]]*pull_request:[[:space:]]*
grep -q 'issue_comment:' .github/workflows/certify.yml
grep -q 'workflow_dispatch:' .github/workflows/certify.yml
grep -q 'required-certification:' .github/workflows/certify.yml
grep -q 'response.data.head.sha' .github/workflows/certify.yml
grep -q '_intent-contracts.yml' .github/workflows/certify.yml
grep -q 'dotnet-production-installer.yml' .github/workflows/certify.yml
grep -q 'dotnet-signed-self-update.yml' .github/workflows/certify.yml
grep -q 'dotnet-broken-update-rollback.yml' .github/workflows/certify.yml
grep -q 'dotnet-production-release-preflight.yml' .github/workflows/certify.yml
grep -Fq '"windows-x64"' .github/workflows/certify.yml

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
  [ "$path" = ".github/workflows/certify.yml" ] && continue
  if grep -q 'github.event.pull_request' "$path"; then
    echo "CI intent ownership violation: stale pull_request event context in $path" >&2
    exit 1
  fi
done

grep -Fq "github.event_name == 'pull_request'" .github/workflows/certify.yml
grep -Fq 'Certification targets:' .github/workflows/certify.yml

grep -q 'AUTHORIZE_PRODUCTION_SIGNING' .github/workflows/dotnet-production-signing.yml

echo 'Agent intent-driven CI ownership GREEN'
 .github/workflows/*.yml | sort)
expected_pr_owners=(
  ".github/workflows/certify.yml"
  ".github/workflows/pr-guard.yml"
)
if [ "${#pr_owners[@]}" -ne "${#expected_pr_owners[@]}" ]; then
  printf 'CI intent ownership violation: only PR Guard plus explicit ready-for-review certification may own pull_request; found: %s\n' "${pr_owners[*]:-none}" >&2
  exit 1
fi
for i in "${!expected_pr_owners[@]}"; do
  if [ "${pr_owners[$i]}" != "${expected_pr_owners[$i]}" ]; then
    printf 'CI intent ownership violation: only PR Guard plus explicit ready-for-review certification may own pull_request; found: %s\n' "${pr_owners[*]:-none}" >&2
    exit 1
  fi
done
grep -Fq 'types: [ready_for_review]' .github/workflows/certify.yml

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
