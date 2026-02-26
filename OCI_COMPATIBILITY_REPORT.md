# OCI Free Tier Compatibility Audit Report

## Section 1: OCI Free Tier Compatibility Verdict
**VERDICT: PASS**
The SentinAI NetGuard project has been successfully adapted for Oracle Cloud Infrastructure (OCI) Always Free Tier (Ampere A1 Compute).

## Section 2: Confirmed ARM-safe Components
The following components have been verified for ARM64 architecture compatibility:
- **Language Runtimes**: 
  - Python 3.9 (Official Docker Image `python:3.9-slim` supports ARM64/v8)
  - Node.js (via Cloudflare Pages / external build)
- **Database**:
  - MongoDB 6.0 (Official Docker Image supports ARM64)
- **ML Dependencies**:
  - `scikit-learn`, `numpy`, `pandas` (ARM64 wheels available on PyPI)
- **Web Server**:
  - `uvicorn`, `fastapi` (Pure Python/Standard implementations)

## Section 3: Fixed or Replaced Dependencies
- **Added**: `oci` (Oracle Cloud Infrastructure SDK) - For Object Storage integration.
- **Added**: `apscheduler` - For periodic background tasks (log archival).
- **Configuration**: Added `deployment/Dockerfile.arm64` specifically tuned for OCI Ampere instances.
- **Configuration**: Added `service/netguard-backend.service` for systemd-based deployment on Ubuntu.

## Section 4: Resource Usage Summary
- **CPU**: 
  - **Backend**: ~5-10% utilization during normal traffic (estimated).
  - **ML Inference**: Low overhead due to lightweight Random Forest model (max_depth=2, n_estimators=30).
  - **Database**: Capped at 1.0 CPU in `docker-compose.arm64.yml`.
- **RAM**:
  - **Total Limit**: 24 GB (OCI Free Tier Limit).
  - **Backend**: ~200MB - 500MB.
  - **MongoDB**: Hard-capped at 2GB (WiredTiger Cache restricted to 1GB) to prevent OOM kills.
  - **Recommended Instance Size**: 2 OCPUs, 12 GB RAM.
- **Storage**:
  - **Local Disk**: Minimal usage. Logs are now rotated and archived to generic Object Storage to prevent disk fill-up.
  - **Object Storage**: Used for long-term retention of `threat_logs`.

## Section 5: Deployment Instructions for OCI
**See `deployment/oci_checklist.md` for the step-by-step guide.**
1. Provision Ampere A1 Instance.
2. Clone Repo.
3. Configure `.env` with OCI Credentials (IP/Key/Bucket).
4. Run `docker-compose -f deployment/docker-compose.arm64.yml up -d`.

## Section 6: Known Limitations
- **Cold Start**: The first time the ML model loads, there may be a 1-2 second latency. In-memory caching resolves this for subsequent requests.
- **Storage Latency**: Archiving to Object Storage is asynchronous but depends on network bandwidth.
- **HTTPS**: The provided Docker Compose does not include a reverse proxy (Nginx/Traefik) for SSL termination. It exposes port 8000 directly. **Production Recommendation**: Use Oracle Load Balancer (Free Tier compatible) or Cloudflare Tunnel.
