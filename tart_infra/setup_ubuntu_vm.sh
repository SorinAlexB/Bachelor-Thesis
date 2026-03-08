#!/bin/bash
# ============================================================
# Tart Ubuntu VM Setup
# ============================================================

# --- Configurare ---
VM_NAME="linux-sandbox"
SSH_USER="test"
SSH_PASSWORD="test"
BASE_IMAGE="ghcr.io/cirruslabs/ubuntu:latest"

# Culori pentru output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# --- 1. Verify Tart installation ---
command -v tart &>/dev/null || err "Tart not installed. Run: brew install cirruslabs/cli/tart"

# --- 2. Delete VM if already existing ---
if tart list | grep -q "^${VM_NAME}"; then
    warn "VM-ul '${VM_NAME}' already created. Deleting and rebuilding..."
    tart delete "${VM_NAME}"
fi

# --- 3. Clone base Ubuntu image ---
log "Clone image ${BASE_IMAGE}..."
tart clone "${BASE_IMAGE}" "${VM_NAME}" || err "Clone failed"

# --- 4. Run VM in background ---
log "Run VM..."
tart run "${VM_NAME}" --no-graphics &
TART_PID=$!

# Wait for ssh connection
log "Wait for booting (~30 seconds)..."
sleep 30

# --- 5. Obtain VMs IP ---
VM_IP=$(tart ip "${VM_NAME}" --wait 60) || err "IP not found"
log "VM run at IP: ${VM_IP}"

# --- 6. Configure ssh ---
DEFAULT_USER="admin"
DEFAULT_PASS="admin"

ssh_exec() {
    sshpass -p "${DEFAULT_PASS}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "${DEFAULT_USER}@${VM_IP}" "$1"
}

log "ConfigVM-ul..."

log "Install openssh-server, sudo, curl, neovim..."
ssh_exec "sudo apt-get update -q && sudo apt-get install -y openssh-server sudo curl neovim"
ssh_exec "sudo mkdir -p /run/sshd"

# Create new user with as sudoer
log "Create user '${SSH_USER}'..."
ssh_exec "sudo useradd -m -s /bin/bash ${SSH_USER} 2>/dev/null || true"
ssh_exec "echo '${SSH_USER}:${SSH_PASSWORD}' | sudo chpasswd"
ssh_exec "sudo usermod -aG sudo ${SSH_USER}"
ssh_exec "echo '${SSH_USER} ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers"

# --- 7. Create a clean snapshot---
tart stop "${VM_NAME}" 2>/dev/null || true
sleep 3
tart run "${VM_NAME}" --no-graphics &
sleep 20

log "Snapshot saved. Config completed!"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Ubuntu VM built!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "  Nume VM  : ${VM_NAME}"
echo -e "  IP       : ${VM_IP}"
echo -e "  Port SSH : 22"
echo -e "  User     : ${SSH_USER}"
echo -e "  Password : ${SSH_PASSWORD}"
echo ""
echo -e "  Connect:"
echo -e "  ${YELLOW}ssh ${SSH_USER}@${VM_IP}${NC}"
echo -e "${GREEN}============================================${NC}"