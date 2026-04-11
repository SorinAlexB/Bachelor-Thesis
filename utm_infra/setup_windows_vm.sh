#!/bin/bash
# ============================================================
# UTM Windows 11 VM Setup
# ============================================================
# Prerequisites (manual steps before running this script):
#   1. Created a Windows 11 VM in UTM named "windows-sandbox"
#   2. Configured port forwarding in UTM:
#        TCP localhost:2222 → guest:22   (SSH)
#   3. Installed Windows 11 with local account: test / test123!
#   4. Copied $HOME/.utm-windows-setup/setup-ssh.ps1 to Windows
#      and ran it as Administrator (this script generates that file)
# ============================================================

# --- Configuration ---
VM_NAME="windows-sandbox"
SSH_USER="test"
SSH_PASSWORD="test"
SSH_HOST="localhost"
SSH_PORT="2222"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

WORK_DIR="$HOME/.utm-windows-setup"
mkdir -p "$WORK_DIR"

# --- 1. Verify dependencies ---
[ -d "/Applications/UTM.app" ] || err "UTM not installed. Get it from: https://mac.getutm.app/"
command -v utmctl &>/dev/null || err "utmctl not found. Add to PATH: export PATH=\"\$PATH:/Applications/UTM.app/Contents/MacOS\""
command -v sshpass &>/dev/null || err "sshpass not found. Install: brew install hudochenkov/sshpass/sshpass"

# --- 2. Generate setup-ssh.ps1 for Windows ---
log "Generating SSH setup script for Windows..."

cat > "$WORK_DIR/setup-ssh.ps1" <<'POWERSHELL'
# Windows SSH Setup - run as Administrator
Write-Host "`n[+] Installing OpenSSH Server..." -ForegroundColor Green
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null

Write-Host "[+] Starting SSH service..." -ForegroundColor Green
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

Write-Host "[+] Configuring firewall..." -ForegroundColor Green
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

Write-Host "[+] Setting PowerShell as default SSH shell..." -ForegroundColor Green
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force | Out-Null

Write-Host "[+] Disabling password expiration for test user..." -ForegroundColor Green
Set-LocalUser -Name "test" -PasswordNeverExpires $true -ErrorAction SilentlyContinue

Write-Host "`n[OK] SSH setup complete. You can now close this window." -ForegroundColor Cyan
pause
POWERSHELL

log "Script saved to: $WORK_DIR/setup-ssh.ps1"
info "Copy this file to the Windows VM and run it as Administrator before continuing."

# --- 3. Check VM exists ---
utmctl list | grep -q "${VM_NAME}" || err "VM '${VM_NAME}' not found. Create it in UTM first."

# --- 4. Start VM ---
log "Starting VM '${VM_NAME}'..."
VM_STATUS=$(utmctl status "${VM_NAME}" 2>/dev/null)
if echo "${VM_STATUS}" | grep -qi "started\|running"; then
    warn "VM already running."
else
    utmctl start "${VM_NAME}" || err "Failed to start VM"
fi

# --- 5. SSH helper ---
ssh_exec() {
    sshpass -p "${SSH_PASSWORD}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=15 \
        -p "${SSH_PORT}" \
        "${SSH_USER}@${SSH_HOST}" \
        "powershell -NoProfile -NonInteractive -Command \"$1\""
}

# --- 6. Wait for SSH ---
log "Waiting for SSH on localhost:${SSH_PORT}..."
SSH_UP=0
for i in $(seq 1 24); do
    if sshpass -p "${SSH_PASSWORD}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        -p "${SSH_PORT}" \
        "${SSH_USER}@${SSH_HOST}" "echo ok" &>/dev/null; then
        log "SSH is up."
        SSH_UP=1
        break
    fi
    warn "SSH not ready, retrying in 10s... (${i}/24)"
    sleep 10
done

[ "$SSH_UP" -eq 1 ] || err "SSH did not become available after 4 minutes. Check port forwarding and that setup-ssh.ps1 was run."

# --- 7. Install tools via winget ---
log "Installing tools via winget..."
ssh_exec "winget install --id Neovim.Neovim -e --silent --accept-package-agreements --accept-source-agreements" || warn "neovim install may have failed, continuing..."
ssh_exec "winget install --id cURL.cURL -e --silent --accept-package-agreements --accept-source-agreements" || warn "curl install may have failed, continuing..."

# --- 8. Stop VM ---
log "Stopping VM for clean state..."
utmctl stop "${VM_NAME}" 2>/dev/null || true
sleep 5

log "Setup completed!"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Windows 11 VM ready!${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "  VM Name  : ${VM_NAME}"
echo -e "  SSH      : ${SSH_HOST}:${SSH_PORT}"
echo -e "  User     : ${SSH_USER}"
echo -e "  Password : ${SSH_PASSWORD}"
echo ""
echo -e "  Connect:"
echo -e "  ${YELLOW}ssh ${SSH_USER}@${SSH_HOST} -p ${SSH_PORT}${NC}"
echo -e "${GREEN}============================================${NC}"
