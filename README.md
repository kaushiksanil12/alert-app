# VulnWatch — Vulnerability Alert Service

A **single-container, self-hosted** security vulnerability monitoring service. Tracks CVEs across 18 technologies, deduplicates against a local store, and posts daily batched alerts to Microsoft Teams.

---

## Quick Start

### 1. Create a `.env` file

```bash
cp .env.example .env
# Edit .env with your actual values
```

Required variables:

| Variable | Description |
|---|---|
| `TEAMS_WEBHOOK_URL` | Microsoft Teams incoming webhook URL |
| `NVD_API_KEY` | NIST NVD API key (see below) |
| `RUN_NOW_TOKEN` | Secret token for the "Run Now" API endpoint |

### 2. Run with Docker Compose

```bash
docker compose up -d
```

### 3. Open the dashboard

```
http://localhost:8080
```

---

## Getting an NVD API Key

The NVD API is free. Without a key, you're limited to 5 requests per 30 seconds (many of the 18 sources use NVD, so this will cause rate-limit errors in a single run).

1. Visit **[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)**
2. Fill in your email and use case
3. You'll receive the key by email within minutes
4. Add it to `.env` as `NVD_API_KEY=your-key-here`

With a key, the limit increases to 50 requests per 10 seconds — more than sufficient for 18 sources.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | *(required)* | Teams incoming webhook for main daily alerts |
| `NVD_API_KEY` | *(required for production)* | NIST NVD API key |
| `RUN_NOW_TOKEN` | *(required)* | Bearer token for `/api/run-now` and acknowledge endpoints |
| `TZ` | `Asia/Kolkata` | Timezone for local-midnight scheduling |
| `DATA_DIR` | `/data` | Directory for the bbolt data file (must be writable) |
| `SOURCES_PATH` | `config/sources.yaml` | Path to the sources config file |
| `MIN_ALERT_SEVERITY` | `LOW` | Minimum severity for Teams alerts (LOW/MEDIUM/HIGH/CRITICAL). Findings below this are still stored. |
| `CRITICAL_WEBHOOK_URL` | *(optional)* | Separate Teams webhook for HIGH/CRITICAL escalations |
| `WEEKLY_DIGEST_WEBHOOK_URL` | *(optional, falls back to TEAMS_WEBHOOK_URL)* | Webhook for weekly digest |
| `WEEKLY_DIGEST_DAY` | `Monday` | Day of week for the weekly digest |
| `FAILURE_ALERT_THRESHOLD` | `3` | Consecutive fetch failures before a meta-alert |
| `RETENTION_DAYS` | `30` | Days to keep full finding records (dedup index never pruned) |
| `LOG_RETENTION_DAYS` | `30` | Days to retain application logs |

---

## Tracked Technologies (18)

Configured in [`config/sources.yaml`](config/sources.yaml) — add or remove technologies here without touching code.

| Technology | Source | Method |
|---|---|---|
| Node.js | nodejs.org RSS | Atom/RSS parse |
| Java / OpenJDK | NVD API | keyword: `openjdk` |
| C++ / GCC | NVD API | keyword: `gcc compiler` |
| Docker | NVD API | keyword: `docker` |
| Git | NVD API | keyword: `git scm` |
| GitLab | NVD API | keyword: `gitlab` |
| AWS | NVD API | keyword: `amazon web services` |
| GCP | NVD API | keyword: `google cloud platform` |
| SonarQube | NVD API | keyword: `sonarqube` |
| React | OSV.dev | ecosystem: npm |
| Python / CPython | NVD API | keyword: `cpython` |
| Azure | NVD API | keyword: `microsoft azure` |
| Ubuntu | Ubuntu USN RSS | RSS parse |
| Trivy | OSV.dev | ecosystem: Go |
| ArgoCD | OSV.dev | ecosystem: Go |
| Kubernetes | NVD API | keyword: `kubernetes` |
| Django | OSV.dev | ecosystem: PyPI |
| Spring Boot | OSV.dev | ecosystem: Maven |

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/` | GET | None | Dashboard |
| `/healthz` | GET | None | Health check + last run timestamp |
| `/api/export.csv` | GET | None | CSV export of all current findings |
| `/api/run-now` | POST | Bearer token | Trigger an immediate scan |
| `/api/acknowledge/{source}/{cve_id}` | POST | Bearer token | Acknowledge a finding |
| `/api/unacknowledge/{source}/{cve_id}` | POST | Bearer token | Reverse an acknowledgement |

### Example: Trigger Run Now

```bash
curl -X POST http://localhost:8080/api/run-now \
  -H "Authorization: Bearer your-run-now-token"
```

### Example: Acknowledge a Finding

```bash
curl -X POST http://localhost:8080/api/acknowledge/django/CVE-2023-41164 \
  -H "Authorization: Bearer your-run-now-token"
```

### Example: Export CSV with filters

```bash
curl "http://localhost:8080/api/export.csv?severity=HIGH&from=2024-01-01"
```

---

## First-Run Baseline Behavior

On the **very first run** for any source, the service silently records all currently-published CVEs as "already seen" — **no alerts are sent**. This prevents a flood of historical CVEs the first time a source is added.

Alerts only fire for CVEs published **after** the baseline run.

---

## Docker Image

```bash
# Build
docker build -t vuln-alert-service .

# Verify image size (must be <100MB)
docker images vuln-alert-service

# Verify non-root
docker inspect vuln-alert-service --format='User: {{.Config.User}}'

# Verify no shell exists in the image
docker run --rm vuln-alert-service sh 2>&1 | head -1
# Expected: "exec: "sh": executable file not found in $PATH" or similar

# Verify no os/exec in codebase
grep -r '"os/exec"' . --include="*.go"
# Expected: no output
```

---

## Domain Allowlist

The service makes outbound HTTPS calls **only** to these domains:

```
api.osv.dev                           # OSV.dev REST API
services.nvd.nist.gov                 # NIST NVD CVE API v2
nodejs.org                            # Node.js security RSS feed
ubuntu.com                            # Ubuntu USN RSS feed
fonts.googleapis.com                  # Dashboard font (optional, can remove)
fonts.gstatic.com                     # Dashboard font (optional, can remove)
```

Lock down firewall egress to these domains for production deployments.

---

## Security Properties

- ✅ Distroless base image (no shell, no package manager)
- ✅ Runs as `nonroot:nonroot` (UID 65532)
- ✅ Read-only root filesystem
- ✅ All Linux capabilities dropped (`cap_drop: ALL`)
- ✅ No `os/exec` anywhere (grep-verifiable)
- ✅ All HTML rendering via `html/template` (auto-escaping)
- ✅ All external content sanitized via bluemonday before storage
- ✅ Secrets in environment variables only, never logged
- ✅ TLS certificate verification always on
- ✅ Bearer token required for all write endpoints
- ✅ Dedup index never pruned (no risk of re-alerting old CVEs)

---

## Adding a New Technology

Edit [`config/sources.yaml`](config/sources.yaml) and add an entry. No code changes required.

```yaml
- name: my_tech          # unique ID (used as store key prefix)
  technology: "My Tech"  # display name in alerts and dashboard
  type: osv              # osv | nvd | nodejs_rss | vendor_rss
  ecosystem: npm         # for osv: npm | PyPI | Go | Maven | ...
  package: my-package    # for osv: exact package name
```

Or for NVD:
```yaml
- name: my_runtime
  technology: "My Runtime"
  type: nvd
  keyword: "my runtime keyword"
  min_severity: HIGH     # optional: override global MIN_ALERT_SEVERITY for this source
```

Restart the container to pick up changes.

---

## .env.example

```bash
# Required
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
NVD_API_KEY=your-nvd-api-key-here
RUN_NOW_TOKEN=a-strong-random-secret-here

# Recommended
TZ=Asia/Kolkata
MIN_ALERT_SEVERITY=MEDIUM

# Optional
# CRITICAL_WEBHOOK_URL=https://outlook.office.com/webhook/...
# WEEKLY_DIGEST_WEBHOOK_URL=https://outlook.office.com/webhook/...
# WEEKLY_DIGEST_DAY=Monday
# FAILURE_ALERT_THRESHOLD=3
# RETENTION_DAYS=30
```
