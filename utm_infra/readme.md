# Windows 11 VM using UTM

UTM is a virtualisation app for macOS that supports x86 and ARM guests via QEMU/Apple Hypervisor. This directory contains scripts for managing a Windows 11 VM used to test vulnerabilities.

## Prerequisites

### 1. Install UTM
```bash
brew install --cask utm
```
Or download from https://mac.getutm.app

### 2. Install utmctl (CLI)
`utmctl` ships with the UTM app. Add it to your PATH:
```bash
export PATH="$PATH:/Applications/UTM.app/Contents/MacOS"
```

### 3. Install sshpass
```bash
brew install hudochenkov/sshpass/sshpass
```

### 4. Create the Windows 11 VM manually
Since UTM has no container-image workflow for Windows (unlike tart), you must:
1. Download a Windows 11 ISO from Microsoft.
2. In UTM: **+** > **Virtualize** > **Windows** — enable TPM and Secure Boot.
3. Attach the ISO, boot, and complete the Windows installation.
4. Name the VM exactly `windows-sandbox`.

### 5. Enable OpenSSH Server inside Windows 11
Open PowerShell as Administrator in the guest:
```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable the service
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

# Allow SSH through Windows Firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 6. Update credentials in setup_windows_vm.sh
Edit the script and set `DEFAULT_USER` and `DEFAULT_PASS` to match your Windows administrator account.

## Usage

### Build (post-install configuration)
```bash
chmod +x *.sh
./build_machines.sh
```

### Start VM
```bash
./start_machines.sh
```

### Stop VM
```bash
./stop_machines.sh
```

### Connect via SSH
```bash
ssh test@<VM_IP>
```

## Notes
- The `test` user is created with password `Test1234!` and is added to the Administrators group.
- IP discovery relies on `utmctl ip-address`; make sure the VM uses a **Shared Network (NAT)** or **Bridged** adapter.
- Windows 11 boots slower than Linux/macOS — the setup script waits up to 2 minutes for SSH.
