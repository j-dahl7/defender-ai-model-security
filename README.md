# AI Model Security Lab — Defender for Cloud + Azure ML

Companion lab for the blog post **"Pickle Is a Loaded Gun: Blocking Malicious AI Models with Defender for Cloud"**.

This lab deploys an Azure Machine Learning workspace, uploads four deliberately crafted model artifacts (one clean, three malicious), enables Microsoft Defender for AI Services' AI model scanner, and wires the resulting alerts into Microsoft Sentinel with analytics rules, a workbook, and a GitHub Actions CI gate.

## What you'll demonstrate

| # | Attack | Payload | Expected Defender alert |
|---|---|---|---|
| 1 | Baseline — clean model | `clean_iris_rf.pkl` (sklearn RandomForest) | *no alert* |
| 2 | Pickle `__reduce__` RCE | `malicious_reduce.pkl` | `Ai.AIModelScan_MalwareDetected` (High) |
| 3 | Exposed secrets in pickled config | `secret_exposed_model.pkl` | `Ai.AIModelScan_SecretDetected` (High) |
| 4 | Unsafe opcode in TorchScript | `unsafe_torchscript.pt` | `Ai.AIModelScan_MalwareDetected` (High) |

## Repository layout

```
labs/defender-ai-model-security/
├── infra/
│   ├── main.bicep              # AML workspace + registry + KV + storage + App Insights
│   ├── sentinel-rules.bicep    # 3 analytics rules + workbook
│   └── workbook.json           # AI Model Security Dashboard
├── payloads/
│   ├── build_clean_model.py
│   ├── build_malicious_reduce.py
│   ├── build_secret_exposed.py
│   ├── build_unsafe_torchscript.py  (requires torch)
│   └── requirements.txt
├── ci/
│   └── github-actions-model-scan.yml  # PR gate — fails build on malicious models
├── scripts/
│   ├── deploy-lab.sh           # One-shot deploy (providers, RG, Defender plans, Bicep, payloads)
│   └── cleanup.sh              # Tear down RG + purge soft-deleted KV
└── README.md
```

## Prerequisites

- Azure subscription with **Owner** or **Contributor** + **Security Admin**.
- Azure CLI 2.60+ with the `ml` extension (`az extension add -n ml`).
- Python 3.11+.
- A Microsoft Sentinel–onboarded Log Analytics workspace (the analytics rules expect `SecurityAlert` to flow via the **Microsoft Defender for Cloud** data connector).
- For the CI gate: GitHub repository with Azure federated credentials (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` OIDC secrets).

## Deploy

```bash
# 1. Sign in
az login
az account set --subscription <your-subscription-id>

# 2. Point the script at your Sentinel workspace
export SENTINEL_WS_ID="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<law>"

# 3. Deploy
./scripts/deploy-lab.sh

# 4. Deploy Sentinel rules against your Sentinel workspace
az deployment group create \
  --resource-group <sentinel-rg> \
  --template-file infra/sentinel-rules.bicep \
  --parameters workspaceName=<sentinel-law-name>
```

## What the deploy does, step by step

1. Registers `Microsoft.MachineLearningServices`, `Microsoft.Security`, `Microsoft.OperationalInsights`, and `Microsoft.Insights` providers.
2. Creates `ai-model-sec-lab-rg` in eastus2.
3. Enables Defender CSPM at the subscription scope (tier `Standard`).
4. Enables Defender for AI Services (tier `Standard`) with the `AIModelScanner` extension ON. **Note:** The portal label reads "AI model security" but the ARM extension name is `AIModelScanner`.
5. Deploys an AML workspace, storage account, Key Vault, App Insights, and an AML registry via Bicep.
6. Builds the clean + malicious model artifacts in a local venv.
7. Registers each artifact as a custom model in the AML workspace.

## Trigger an immediate scan

Defender for AI Services scans registered models **once a week** by default. To get alerts faster:

**Option A — Portal:**
AML workspace → Models → select a model → *Security findings* → *Scan now*.

**Option B — Defender for Cloud CLI** (great for CI/CD):
```bash
# Install
curl -sL https://aka.ms/defender-cli/install.sh | bash

# Scan a local model
defender scan model ./payloads/artifacts/malicious_reduce.pkl \
  --modelscanner-Output malicious_reduce.sarif
```

The SARIF file is consumable by GitHub code scanning, Azure DevOps, or any SARIF-aware quality gate.

## Expected alerts

Within ~10 minutes of a scan completing, you should see these in Defender for Cloud → Security alerts (and, via the Defender connector, in the `SecurityAlert` table in Sentinel):

- `Ai.AIModelScan_MalwareDetected` — High severity, MITRE T1195 (Supply Chain Compromise)
- `Ai.AIModelScan_SecretDetected` — High severity
- `Ai.AIModelScan_UnsafeOperatorDetected` — High severity (if surfaced separately)

## Sentinel analytics rules

Three scheduled rules deploy alongside the workbook:

| Rule | Frequency | Signal |
|------|-----------|--------|
| Malicious AI model uploaded | 5 min | Any `Ai.AIModelScan*` alert |
| Repeat risky model uploader | 1 hour over 7 days | Same identity with 2+ flagged models |
| Model deployed before scan completed | 1 hour over 24h | AML endpoint write without a prior scan verdict |

Each uses the `union isfuzzy=true` fallback pattern so the rules validate even before the first real alert arrives.

## GitHub Actions CI gate

`.github/workflows/model-scan.yml` (symlinked from `ci/github-actions-model-scan.yml`) runs on every PR that touches `models/` or `payloads/`. It:

1. Authenticates to Azure via OIDC.
2. Installs the Defender for Cloud CLI.
3. Runs `defender scan model` against every artifact, emitting SARIF.
4. Uploads SARIF to GitHub's Security tab.
5. Fails the build if any artifact comes back unsafe.

## Cleanup

```bash
./scripts/cleanup.sh
```

This deletes the resource group (async) and purges soft-deleted Key Vaults so subsequent redeploys with the same name succeed. Subscription-level Defender plans stay on — disable manually if you don't want them for real workloads.

## Safety notes

- The malicious payloads drop a harmless sentinel file to `/tmp` on unpickle. They do **not** reach out to the network or execute anything destructive. Still, only run them in a disposable sandbox.
- The "exposed secret" payload uses format-valid but entirely **fake** credentials (the canonical `AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` used in AWS docs). Do not substitute real values.

## Related posts

- [AKS Runtime Security with Defender for Containers](https://ninelivesinfosec.com/blog/aks-runtime-security-defender/) — the same code-to-runtime story, applied to containers.
- [Secure Your Container Supply Chain](https://ninelivesinfosec.com/blog/container-sbom-signing-attestation/) — SBOM + signing + attestation.

## References

- [AI model security (Defender for Cloud docs)](https://learn.microsoft.com/azure/defender-for-cloud/ai-model-security)
- [Enable threat protection for AI services](https://learn.microsoft.com/azure/defender-for-cloud/ai-onboarding)
- [Defender for Cloud CLI — AI Model Scan](https://learn.microsoft.com/azure/defender-for-cloud/defender-cli-syntax#ai-model-scan)
- [Alerts for AI services](https://learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads)
