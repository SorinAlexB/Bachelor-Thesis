#!/bin/bash
# ============================================================
# Tart macOS VM Setup
# ============================================================

# --- Configurare ---
VM_NAME="macos-sandbox"
SSH_USER="test"
SSH_PASSWORD="test"
BASE_IMAGE="ghcr.io/cirruslabs/macos-sequoia-base:latest"

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
    warn "VM-ul '${VM_NAME}' already exists. Deleting and rebuilding..."
    tart delete "${VM_NAME}"
fi

# --- 3. Clone base macOS image ---
log "Cloning image ${BASE_IMAGE}..."
log "Note: macOS images are large (~25GB), this may take a while..."
tart clone "${BASE_IMAGE}" "${VM_NAME}" || err "Clone failed"

# --- 4. Run VM in background (no GUI) ---
log "Running VM..."
tart run "${VM_NAME}" --no-graphics &
TART_PID=$!

# Wait for SSH — macOS takes longer to boot than Ubuntu
log "Waiting for boot (~60 seconds)..."
sleep 60

# --- 5. Obtain VM's IP ---
VM_IP=$(tart ip "${VM_NAME}" --wait 120) || err "IP not found"
log "VM running at IP: ${VM_IP}"

# --- 6. Configure SSH ---
# Default credentials for Cirrus Labs macOS images
DEFAULT_USER="admin"
DEFAULT_PASS="admin"

ssh_exec() {
    sshpass -p "${DEFAULT_PASS}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=15 \
        "${DEFAULT_USER}@${VM_IP}" "$1"
}

log "Configuring VM..."

# Enable Remote Login (SSH) on macOS — equivalent to System Settings > Sharing > Remote Login
log "Enabling SSH (Remote Login)..."
ssh_exec "sudo systemsetup -setremotelogin on 2>/dev/null || true"
ssh_exec "sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true"

# Install Homebrew (package manager for macOS — equivalent of apt)
log "Installing Homebrew..."
ssh_exec '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/null'

# Add brew to PATH for Apple Silicon
ssh_exec 'echo '\''eval "$(/opt/homebrew/bin/brew shellenv)"'\'' >> ~/.zprofile'
ssh_exec 'eval "$(/opt/homebrew/bin/brew shellenv)" && brew install curl neovim'

# Create new user with sudo privileges
log "Creating user '${SSH_USER}'..."
ssh_exec "sudo dscl . -create /Users/${SSH_USER}"
ssh_exec "sudo dscl . -create /Users/${SSH_USER} UserShell /bin/zsh"
ssh_exec "sudo dscl . -create /Users/${SSH_USER} RealName '${SSH_USER}'"
ssh_exec "sudo dscl . -create /Users/${SSH_USER} UniqueID 502"
ssh_exec "sudo dscl . -create /Users/${SSH_USER} PrimaryGroupID 20"
ssh_exec "sudo dscl . -create /Users/${SSH_USER} NFSHomeDirectory /Users/${SSH_USER}"
ssh_exec "sudo dscl . -passwd /Users/${SSH_USER} '${SSH_PASSWORD}'"
ssh_exec "sudo dscl . -append /Groups/admin GroupMembership ${SSH_USER}"
ssh_exec "sudo mkdir -p /Users/${SSH_USER} && sudo chown ${SSH_USER}:staff /Users/${SSH_USER}"

# Grant passwordless sudo
ssh_exec "echo '${SSH_USER} ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers"

# --- 7. Stop, snapshot, restart ---
log "Creating clean snapshot..."
tart stop "${VM_NAME}" 2>/dev/null || true
sleep 5
tart run "${VM_NAME}" --no-graphics &
sleep 30

log "Snapshot saved. Config completed!"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  macOS VM built!${NC}"
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