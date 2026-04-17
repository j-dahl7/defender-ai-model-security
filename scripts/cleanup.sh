#!/usr/bin/env bash
# Tear down the AI Model Security lab.
#
# Scope:
#   - Deletes the resource group.
#   - Does NOT change subscription-level Defender plans (CSPM / AI) because
#     you may want to keep them on for your real workloads. Disable manually
#     if needed: az security pricing create --name AI --tier Free
set -euo pipefail

RG="${RG:-ai-model-sec-lab-rg}"

if az group show --name "$RG" --only-show-errors >/dev/null 2>&1; then
  echo "Deleting resource group $RG (this takes ~5 minutes)..."
  az group delete --name "$RG" --yes --no-wait
else
  echo "Resource group $RG not found — nothing to delete."
fi

# Purge soft-deleted Key Vault so a redeploy with the same name works.
# Bicep names the KV amlmodelsec-kv-<first-8-of-suffix>; use a wildcard list.
for kv in $(az keyvault list-deleted --query "[?starts_with(name,'amlmodelsec-kv-')].name" -o tsv 2>/dev/null); do
  echo "Purging deleted Key Vault: $kv"
  az keyvault purge --name "$kv" --no-wait 2>/dev/null || true
done

echo "Cleanup initiated. RG deletion runs in the background."
