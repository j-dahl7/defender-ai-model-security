#!/usr/bin/env bash
# Deploy the AI Model Security lab end-to-end.
#
# Flow:
#   1. Ensure providers registered
#   2. Create RG
#   3. Enable Defender CSPM + Defender for AI Services (subscription scope)
#   4. Toggle AI model security component on
#   5. Deploy Bicep (AML workspace + registry + deps)
#   6. Build payloads
#   7. Register payloads as models in AML workspace
#   8. Print follow-up verification steps
#
# Requires: az cli with ml extension, Python 3.11+, owner on the subscription.

set -euo pipefail

LOCATION="${LOCATION:-eastus2}"
RG="${RG:-ai-model-sec-lab-rg}"
SENTINEL_WS_ID="${SENTINEL_WS_ID:-/subscriptions/4d77f4f1-6176-4ae9-bc55-a91f677d6d9d/resourceGroups/sentinel-urbac-lab-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-urbac-lab-law}"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

say "Verifying providers"
for ns in Microsoft.MachineLearningServices Microsoft.Security Microsoft.OperationalInsights Microsoft.Insights; do
  state=$(az provider show -n "$ns" --query registrationState -o tsv)
  if [[ "$state" != "Registered" ]]; then
    echo "Registering $ns (state=$state)"
    az provider register --namespace "$ns" >/dev/null
  fi
done

say "Creating resource group $RG in $LOCATION"
az group create --name "$RG" --location "$LOCATION" --only-show-errors -o none

say "Enabling Defender CSPM plan"
az security pricing create \
  --name CloudPosture \
  --tier Standard \
  --only-show-errors -o none

say "Enabling Defender for AI Services plan"
az security pricing create \
  --name AI \
  --tier Standard \
  --only-show-errors -o none || true  # extension-name sometimes varies

# AI model security is a sub-component toggle on the AI plan, surfaced via
# the `AIModelScanner` extension (not "AIModelSecurity" — the portal label
# and the API name differ as of April 2026). The extensions list uses a PUT
# that replaces the full array, so we also re-enable AIPromptEvidence to
# preserve the default posture.
say "Toggling AI model security (AIModelScanner) + prompt evidence"
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Security/pricings/AI?api-version=2024-01-01" \
  --body '{"properties":{"pricingTier":"Standard","extensions":[{"name":"AIModelScanner","isEnabled":"True"},{"name":"AIPromptEvidence","isEnabled":"True"}]}}' \
  --only-show-errors -o none

say "Deploying Bicep infrastructure"
OUTPUTS=$(az deployment group create \
  --resource-group "$RG" \
  --template-file "$LAB_DIR/infra/main.bicep" \
  --parameters sentinelWorkspaceId="$SENTINEL_WS_ID" location="$LOCATION" \
  --query properties.outputs -o json)

WORKSPACE_NAME=$(echo "$OUTPUTS" | jq -r '.workspaceName.value')
REGISTRY_NAME=$(echo "$OUTPUTS" | jq -r '.registryName.value')

say "Workspace: $WORKSPACE_NAME"
say "Registry:  $REGISTRY_NAME"

say "Building payloads"
PAYLOAD_DIR="$LAB_DIR/payloads"
if [[ ! -d "$PAYLOAD_DIR/.venv" ]]; then
  python3 -m venv "$PAYLOAD_DIR/.venv"
  "$PAYLOAD_DIR/.venv/bin/pip" install --quiet scikit-learn joblib numpy
fi
"$PAYLOAD_DIR/.venv/bin/python" "$PAYLOAD_DIR/build_clean_model.py"
"$PAYLOAD_DIR/.venv/bin/python" "$PAYLOAD_DIR/build_malicious_reduce.py"
"$PAYLOAD_DIR/.venv/bin/python" "$PAYLOAD_DIR/build_secret_exposed.py"

say "Registering models in AML workspace"
cd "$PAYLOAD_DIR/artifacts"
for f in clean_iris_rf.pkl malicious_reduce.pkl secret_exposed_model.pkl; do
  model_name="${f%.pkl}"
  model_name="${model_name//_/-}"
  echo "  -> $model_name"
  az ml model create \
    --name "$model_name" \
    --path "$f" \
    --type "custom_model" \
    --resource-group "$RG" \
    --workspace-name "$WORKSPACE_NAME" \
    --only-show-errors 1>/dev/null
done

say "Done. Next steps:"
cat <<'NEXT'
  1. Defender for Cloud scans models weekly. For an immediate scan, use the
     Defender CLI:
        defender scan model <path-to-model.pkl> --modelscanner-Output scan.sarif
     Or trigger a manual scan from the AML workspace UI > Models > each model.

  2. Watch for alerts in Defender for Cloud > Security alerts. Expected alert
     types:
        - Ai.AIModelScan_MalwareDetected   (on malicious_reduce.pkl)
        - Ai.AIModelScan_SecretDetected    (on secret_exposed_model.pkl)

  3. Alerts flow to Sentinel via the Defender XDR data connector. The
     analytics rules in infra/sentinel-rules.bicep light up the workbook.

  4. Tear down:   ./scripts/cleanup.sh
NEXT
