# OCI Always Free Tier Deployment Checklist

## 1. Prerequisites
- [ ] **Oracle Cloud Account**: Active account with access to "Always Free" resources.
- [ ] **Instance**: An **Ampere A1 Compute Instance** (ARM64) with Ubuntu 20.04 or 22.04.
    - Recommended: 2-4 OCPUs, 12-24 GB RAM.
- [ ] **Networking**:
    - VCN created with a Public Subnet.
    - Security List Ingress Rules:
        - TCP 80 (HTTP)
        - TCP 443 (HTTPS)
        - TCP 8000 (API)
        - TCP 22 (SSH)

## 2. Environment Setup (On OCI Instance)
1. **SSH into the instance**:
   ```bash
   ssh ubuntu@<your-instance-ip>
   ```
2. **Install Docker & Compose**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y docker.io docker-compose
   sudo usermod -aG docker $USER
   # Log out and back in for group changes to take effect
   ```
3. **Clone Repository (or Copy Files)**:
   - Upload your project files to `~/SentinAI-netguard`.

## 3. Configuration
1. **Create .env file**:
   ```bash
   cd ~/SentinAI-netguard
   cp .env.example .env
   nano .env
   ```
   - *Important*: If using Instance Principals (recommended), you can leave `OCI_CONFIG_PROFILE` as DEFAULT and ensure your instance has a Dynamic Group and Policy allowing object storage access.
   - *Policy Example*: `Allow dynamic-group SentinAI-Instances to manage objects in tenancy`

## 4. Deployment (Docker Method) - Recommended
1. **Build and Run**:
   ```bash
   # Use the ARM64 compose file
   docker-compose -f deployment/docker-compose.arm64.yml up -d --build
   ```
2. **Verify Containers**:
   ```bash
   docker ps
   # Should see netguard-backend and netguard-db
   ```
3. **Check Logs**:
   ```bash
   docker logs -f netguard-backend
   ```

## 5. Deployment (Systemd Method) - Alternative
1. **Install Python & Venv**:
   ```bash
   sudo apt-get install -y python3-pip python3-venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r backend/requirements.txt
   ```
2. **Setup Service**:
   ```bash
   sudo cp deployment/netguard-backend.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable netguard-backend
   sudo systemctl start netguard-backend
   ```

## 6. Access & Verification
- **API Health Check**: `curl http://localhost:8000/api/health`
- **Public Access**: Open `http://<instance-ip>:8000/docs` in your browser.
- **Frontend**: Connect your Cloudflare Pages to the backend IP (ensure CORS in `backend/api_gateway.py` allows your Cloudflare domain).

## 7. Storage Verification
- Check OCI Console -> Object Storage -> `sentinai-logs` bucket.
- Verify that `threat_logs/` JSON files appear after ~10 traffic bursts.
