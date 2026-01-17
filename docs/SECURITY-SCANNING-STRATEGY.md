# Security Scanning Strategy Guide

A practical guide to implementing security scanning across your development lifecycle. This document helps you understand **what to scan, where to scan it, and why** — maximizing security coverage while minimizing cost and developer friction.

---

## The Problem with CI/CD-Only Scanning

Many teams make the mistake of running all security scans in CI/CD pipelines. While better than nothing, this approach has significant drawbacks:

| Issue | Impact |
|-------|--------|
| **Secrets caught too late** | Already in git history — requires rotation + history rewrite |
| **Full scans every commit** | 99% of commits don't touch config files — wasted compute |
| **Slow feedback loops** | Developer has context-switched by the time scan completes |
| **Alert fatigue** | Same warnings on unchanged files every build |
| **Blocking on non-issues** | Old issues in unchanged code block new features |

### The Cost Reality

```
Traditional approach:
  100 commits/day × 5 min scan × $0.008/min = $4/day = $1,460/year
  
Smart approach:
  10 config changes/day × 30 sec scan = $0.04/day = $15/year
```

---

## The "Shift Left, Scan Right" Principle

Different security concerns are best addressed at different stages:

```
Development Timeline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  IDE/Editor    Pre-commit    Pull Request    Merge    Deploy    Runtime
      │              │              │            │         │          │
      ▼              ▼              ▼            ▼         ▼          ▼
  ┌────────┐   ┌──────────┐   ┌─────────┐   ┌──────┐  ┌───────┐  ┌────────┐
  │Secrets │   │ Secrets  │   │ Config  │   │      │  │Runtime│  │Monitor │
  │  Live  │   │  Block   │   │ Changes │   │ Skip │  │ Gate  │  │  Drift │
  │Feedback│   │  Commit  │   │  Only   │   │      │  │       │  │        │
  └────────┘   └──────────┘   └─────────┘   └──────┘  └───────┘  └────────┘

  ◄─────────────────────────────────────────────────────────────────────────►
  Cheapest                                                        Most Accurate
  Fastest Feedback                                                Actual State
```

**Key insight:** Catch issues as early as possible, but validate as late as necessary.

---

## Recommended Scanning Strategy

### Stage 1: IDE / Editor (Immediate Feedback)

**What to scan:** Secrets, obvious syntax errors  
**Cost:** Zero (runs locally)  
**Feedback time:** Instant  

```
┌─────────────────────────────────────────────────┐
│  IDE Plugin Benefits                            │
├─────────────────────────────────────────────────┤
│  ✓ Highlights secrets as you type              │
│  ✓ No context switch needed                    │
│  ✓ Developer learns patterns                   │
│  ✓ Zero CI cost                                │
└─────────────────────────────────────────────────┘
```

**Recommended tools:**
- VS Code: [GitLens](https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens), [Secret Lens](https://marketplace.visualstudio.com/items?itemName=perkinsandwill.secret-lens)
- JetBrains: Built-in secret detection
- Any editor: Configure linting rules

---

### Stage 2: Pre-commit Hook (Gate Before Git)

**What to scan:** Secrets, credentials, API keys  
**Cost:** Zero (runs locally)  
**Feedback time:** 1-5 seconds  
**Blocks:** Commit (before it enters history)

This is the **highest-value security investment** you can make:

```
┌─────────────────────────────────────────────────┐
│  Why Pre-commit for Secrets?                    │
├─────────────────────────────────────────────────┤
│                                                 │
│  WITHOUT pre-commit:                            │
│    Developer commits secret                     │
│         ↓                                       │
│    Secret enters git history                    │
│         ↓                                       │
│    CI catches it 5 minutes later               │
│         ↓                                       │
│    Must rotate secret + rewrite git history    │
│         ↓                                       │
│    Secret may already be in forks/clones       │
│                                                 │
│  WITH pre-commit:                               │
│    Developer tries to commit secret            │
│         ↓                                       │
│    Hook blocks immediately                      │
│         ↓                                       │
│    Developer fixes, commits clean code         │
│         ↓                                       │
│    Secret never enters history ✓               │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Implementation with Gitleaks:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

**Implementation with Husky (Node.js projects):**

```json
// package.json
{
  "scripts": {
    "prepare": "husky install"
  },
  "devDependencies": {
    "husky": "^8.0.0"
  }
}
```

```bash
# .husky/pre-commit
#!/bin/sh
gitleaks protect --staged --verbose
```

---

### Stage 3: Pull Request CI (Changed Files Only)

**What to scan:** Configuration misconfigurations, security best practices  
**Cost:** Low (only changed files)  
**Feedback time:** 30 seconds - 2 minutes  
**Blocks:** Merge to main branch

**Key principle:** Only scan what changed.

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  pull_request:
    paths:
      # Only trigger when config files change
      - '**.conf'
      - '**.yaml'
      - '**.yml'
      - '**.json'
      - '**.env*'
      - '**.ini'
      - '**/Dockerfile'
      - '**/docker-compose*'

jobs:
  scan-changed-configs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Get changed config files
        id: changed
        run: |
          files=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | \
                  grep -E '\.(conf|yaml|yml|json|env|ini)$' || echo "")
          echo "files=$files" >> $GITHUB_OUTPUT
          echo "Changed config files:"
          echo "$files"
      
      - name: Scan changed configs
        if: steps.changed.outputs.files != ''
        run: |
          for file in ${{ steps.changed.outputs.files }}; do
            echo "Scanning: $file"
            node config-scanner.js "$file" || exit 1
          done
```

**What NOT to do:**
```yaml
# ❌ DON'T: Full scan on every PR
- name: Scan everything
  run: node config-scanner.js . --recursive  # Wasteful!
```

---

### Stage 4: Merge to Main (Skip or Minimal)

**What to scan:** Nothing new (already scanned in PR)  
**Cost:** Zero  

If you've properly scanned in the PR stage, there's no need to re-scan on merge. The code hasn't changed.

```yaml
# Only run quick smoke test, not full scan
on:
  push:
    branches: [main]

jobs:
  smoke-test:
    runs-on: ubuntu-latest
    steps:
      - name: Quick validation
        run: echo "PR was already scanned - skipping redundant scan"
```

---

### Stage 5: Deployment Gate (Runtime Configs)

**What to scan:** Actual deployed configurations  
**Cost:** Low  
**Feedback time:** 1-2 minutes  
**Blocks:** Deployment to production

This catches issues that source scanning misses:
- Environment-specific configs
- Configs generated at deploy time
- Runtime configuration drift
- Secrets injected via environment

```yaml
# deployment-gate.yml
deploy-production:
  runs-on: ubuntu-latest
  environment: production
  steps:
    - name: Deploy to staging
      run: kubectl apply -f manifests/ --dry-run=server
    
    - name: Extract deployed configs
      run: |
        kubectl get configmap app-config -o yaml > deployed-config.yaml
        kubectl get secret app-secrets -o yaml > deployed-secrets.yaml
    
    - name: Scan deployed configs
      run: |
        node config-scanner.js deployed-config.yaml
        # Note: Be careful with secrets - scan patterns, not values
    
    - name: Scan container for misconfigs
      run: |
        # Scan the actual nginx config inside the container
        docker run --rm myapp:${{ github.sha }} cat /etc/nginx/nginx.conf > nginx.conf
        node config-scanner.js nginx.conf
```

---

### Stage 6: Scheduled Full Audit (Weekly/Monthly)

**What to scan:** Everything, comprehensively  
**Cost:** Medium (but infrequent)  
**Feedback time:** N/A (async report)  
**Blocks:** Nothing (informational)

```yaml
# .github/workflows/weekly-audit.yml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM UTC
  workflow_dispatch:  # Allow manual trigger

jobs:
  full-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Full configuration scan
        run: |
          node config-scanner.js . --json > audit-report.json
        continue-on-error: true  # Don't fail - this is informational
      
      - name: Generate report
        run: |
          echo "## Weekly Security Audit" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          cat audit-report.json | jq -r '.totalFindings' | \
            xargs -I {} echo "**Total findings:** {}" >> $GITHUB_STEP_SUMMARY
      
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-${{ github.run_number }}
          path: audit-report.json
      
      - name: Notify security team
        if: always()
        run: |
          # Send to Slack, email, or security dashboard
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{"text": "Weekly security audit complete. See artifacts."}'
```

---

## Summary: What to Scan Where

| Stage | Scan Type | Cost | Blocks? | Catches |
|-------|-----------|------|---------|---------|
| **IDE** | Secrets (live) | Free | No | Early mistakes |
| **Pre-commit** | Secrets | Free | Yes | Before history |
| **PR CI** | Changed configs | Low | Yes | Config issues |
| **Merge** | Skip | Zero | No | (Already scanned) |
| **Deploy** | Runtime configs | Low | Yes | Actual state |
| **Weekly** | Full audit | Medium | No | Drift, coverage |

---

## Scan Type Recommendations

| Security Concern | Best Stage | Why |
|-----------------|------------|-----|
| **Hardcoded secrets** | Pre-commit | Catch before git history |
| **API keys & tokens** | Pre-commit | Never enter repo |
| **Config misconfigs** | PR CI (changed files) | Fast, targeted feedback |
| **Network exposure** | Deploy gate | Scan actual deployed config |
| **TLS/SSL settings** | Deploy gate | Environment-specific |
| **Debug mode** | PR CI + Deploy | Catch early, verify at deploy |
| **Container security** | Registry scan | Scan built images |
| **IaC (Terraform)** | PR CI | Plan-time validation |
| **Compliance audit** | Scheduled | Comprehensive, async |

---

## Anti-Patterns to Avoid

### ❌ Scanning everything on every commit

```yaml
# BAD: Full recursive scan on every push
on: [push]
jobs:
  scan:
    steps:
      - run: security-scan --recursive .  # Expensive, slow, wasteful
```

### ❌ Blocking PRs on old issues

```yaml
# BAD: Fails PR due to issues in unchanged files
- run: scan-all-the-things || exit 1
```

### ❌ Secrets scanning only in CI

```yaml
# BAD: By the time CI catches it, secret is in git history
on: [push]
jobs:
  check-secrets:
    steps:
      - run: gitleaks detect  # Too late!
```

### ❌ Ignoring deployment-time configs

```yaml
# BAD: Only scanning source, not deployed state
- run: scan-configs manifests/  # Misses runtime config!
```

---

## Getting Started Checklist

- [ ] **Today:** Install pre-commit hook for secrets (gitleaks)
- [ ] **This week:** Configure PR workflow to scan changed files only
- [ ] **This month:** Add deployment gate scanning
- [ ] **Ongoing:** Set up weekly audit reports

---

## Tools Reference

| Category | Tool | Best For |
|----------|------|----------|
| **Secrets (pre-commit)** | [Gitleaks](https://github.com/gitleaks/gitleaks) | Blocking commits with secrets |
| **Secrets (audit)** | [truffleHog](https://github.com/trufflesecurity/trufflehog) | Scanning git history |
| **Config scanning** | UC Software Scan | Multi-ecosystem config analysis |
| **Container scanning** | [Trivy](https://github.com/aquasecurity/trivy) | Images + IaC |
| **IaC scanning** | [Checkov](https://github.com/bridgecrewio/checkov) | Terraform, CloudFormation |
| **Kubernetes** | [kubesec](https://kubesec.io/) | K8s manifest security |

---

## See Also

- [Software Misconfiguration Scanner](./SOFTWARE-MISCONFIGURATIONS.md) — Technical details on config scanning
- [UC Software Scan Action](../README.md) — Main documentation
- [Example Workflows](../examples/) — Ready-to-use workflow templates
