#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# macOS base64 wraps liniile; tr -d '\n' îl face single-line
CA_BUNDLE=$(cat "$REPO_ROOT/tls/ca.crt" | base64 | tr -d '\n')

sed "s|CA_BUNDLE_PLACEHOLDER|${CA_BUNDLE}|g" \
  "$REPO_ROOT/k8s/validating-webhook.yaml.tpl" \
  | kubectl apply -f -

echo "ValidatingWebhookConfiguration applied successfully"
