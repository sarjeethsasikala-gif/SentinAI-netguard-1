#!/bin/bash
# ------------------------------------------------------------------
# Strategy: Free Tier Maximization
# Instance: t2.micro (1 vCPU, 1GB RAM)
# OS: Ubuntu 22.04 LTS
# Goal: Run Full ML Pipeline without OOM Kills
# ------------------------------------------------------------------

set -e

# --- 1. Swap Space (CRITICAL for ML on 1GB RAM) ---
# Without this, the Pandas/Sklearn load will crash the instance immediately.
echo "[Boostrap] Creating 2GB Swap File..."
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
echo "vm.swappiness=10" >> /etc/sysctl.conf
sysctl -p

# --- 2. Install Dependencies ---
echo "[Bootstrap] Installing Docker & CloudWatch Agent..."
apt-get update
apt-get install -y docker.io docker-compose amazon-cloudwatch-agent

# --- 3. Configure CloudWatch Agent ---
# Expects config file to be present in repo (we will pull it)
# For now, we seed a basic config if repo pull fails or is manual
cat <<EOF > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "metrics": {
    "append_dimensions": {
      "InstanceId": "\${aws:InstanceId}"
    },
    "metrics_collected": {
      "mem": {
        "measurement": ["mem_used_percent"],
        "metrics_collection_interval": 60
      },
      "swap": {
        "measurement": ["swap_used_percent"],
        "metrics_collection_interval": 60
      }
    }
  }
}
EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

# --- 4. Deploy Application ---
# Ideally, this clone part should be replaced by User Data parameters or an AMI
# But for a raw generic script:
echo "[Bootstrap] Deploying SentinAI NetGuard..."
cd /home/ubuntu
# Note: In a real scenario, we'd use a git token or pre-baked AMI.
# For now, we assume the user might scp the files or clone manually.
# Just creating the directory to signal readiness.
mkdir -p SentinAI-netguard

# Enable Docker
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

echo "[Bootstrap] Done. Instance Ready."
