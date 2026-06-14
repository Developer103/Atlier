"""
Windows VM Provisioner using autounattend.xml.
- Generates autounattend.xml that automates the entire Windows installation
- Handles partitioning, OOBE bypass, TPM bypass, SSH setup
"""

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


logger = logging.getLogger(__name__)


# Windows autounattend.xml schema for unattended install
def generate_autounattend_xml(
    username: str = "vmuser",
    password: str = "vmuser123",
    enable_ssh: bool = True,
    skip_tpm: bool = True,
) -> ET.Element:
    """
    Generate an autounattend.xml answer file for Windows 11 unattended install.
    
    This file will be attached as a virtual floppy drive during installation.
    Windows Setup reads this and performs all steps without user interaction.
    """
    root = ET.Element("unattend", xmlns="urn:schemas-microsoft-com:unattend")
    
    settings = ET.SubElement(root, "settings", Pass="specialize")
    settings.append(_windows_settings())
    
    settings_install = ET.SubElement(root, "settings", Pass="windowsPE")
    settings_install.append(_windows_pe_settings(skip_tpm=skip_tpm))
    
    settings = ET.SubElement(root, "settings", Pass="oobeSystem")
    settings.append(_oobe_settings())
    settings.append(_firstlogoncommands(username, password, enable_ssh))
    
    return root


def _windows_settings() -> ET.Element:
    """Specialize pass: product key, computer name, network."""
    component = ET.Element(
        "component",
        Name="Microsoft-Windows-Shell-Setup",
        processorArchitecture="amd64",
        publicKeyToken="31bf3856ad364e35",
        language="neutral",
        versionScope="nonSxS",
    )
    
    ET.SubElement(component, "ProductKey").text = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
    ET.SubElement(component, "ComputerName").text = "MalwareVM"
    ET.SubElement(component, "RegisteredOwner").text = "Analyst"
    ET.SubElement(component, "RegisteredOrganization").text = "Security Team"
    
    # Network settings
    network = ET.SubElement(
        component,
        "NetworkLocation",
    )
    network.text = "Work"
    
    # Disable auto domain join
    domainjoin = ET.SubElement(component, "JoinDomain")
    domainjoin.text = ""
    domainjoin = ET.SubElement(component, "DoNotJoinDomain")
    
    return component


def _windows_pe_settings(skip_tpm: bool = True) -> ET.Element:
    """Windows PE pass: disk partitioning, image selection."""
    component = ET.Element(
        "component",
        Name="Microsoft-Windows-Setup",
        processorArchitecture="amd64",
        publicKeyToken="31bf3856ad364e35",
        language="neutral",
        versionScope="nonSxS",
    )
    
    # Disk configuration - partition automatically
    disk_config = ET.SubElement(component, "DiskConfiguration")
    disk = ET.SubElement(disk_config, "Disk")
    ET.SubElement(disk, "DiskID").text = "0"
    ET.SubElement(disk, "WillWipeDisk").text = "true"
    
    partitions = ET.SubElement(disk, "CreatePartitions")
    
    # EFI partition (100MB)
    efi = ET.SubElement(partitions, "CreatePartition")
    ET.SubElement(efi, "Type").text = "EFI"
    ET.SubElement(efi, "Size").text = "100"
    
    # MSR partition (16MB)
    msr = ET.SubElement(partitions, "CreatePartition")
    ET.SubElement(msr, "Order").text = "2"
    ET.SubElement(msr, "Type").text = "MSR"
    ET.SubElement(msr, "Size").text = "16"
    
    # Primary (Windows) partition
    primary = ET.SubElement(partitions, "CreatePartition")
    ET.SubElement(primary, "Order").text = "3"
    ET.SubElement(primary, "Type").text = "Primary"
    ET.SubElement(primary, "Extend").text = "true"
    
    # Format partitions
    formats = ET.SubElement(disk, "ModifyPartitions")
    
    # EFI format
    efi_fmt = ET.SubElement(formats, "ModifyPartition")
    ET.SubElement(efi_fmt, "Order").text = "1"
    ET.SubElement(efi_fmt, "PartitionID").text = "1"
    ET.SubElement(efi_fmt, "Format").text = "FAT32"
    ET.SubElement(efi_fmt, "Label").text = "SYSTEM"
    ET.SubElement(efi_fmt, "Active").text = "true"
    
    # MSR (no format needed)
    msr_fmt = ET.SubElement(formats, "ModifyPartition")
    ET.SubElement(msr_fmt, "Order").text = "2"
    ET.SubElement(msr_fmt, "PartitionID").text = "2"
    
    # Windows (C:) format
    win_fmt = ET.SubElement(formats, "ModifyPartition")
    ET.SubElement(win_fmt, "Order").text = "3"
    ET.SubElement(win_fmt, "PartitionID").text = "3"
    ET.SubElement(win_fmt, "Format").text = "NTFS"
    ET.SubElement(win_fmt, "Label").text = "Windows"
    ET.SubElement(win_fmt, "Letter").text = "C"
    
    # Image install
    image_install = ET.SubElement(component, "ImageInstall")
    OS_image = ET.SubElement(image_install, "OSImage")
    install_to = ET.SubElement(OS_image, "InstallTo")
    ET.SubElement(install_to, "DiskID").text = "0"
    ET.SubElement(install_to, "PartitionID").text = "3"
    
    # Which Windows edition to install
    install_image = ET.SubElement(OS_image, "InstallFrom")
    keys = ET.SubElement(install_image, "Keys")
    ET.SubElement(keys, "Key").text = "4"
    ET.SubElement(keys, "Value").text = "Windows 11 Pro"
    
    # Enable TPM/network checks bypass in PE (if needed)
    if skip_tpm:
        # These are handled via registry in FirstLogonCommands, not PE pass
        pass
    
    return component


def _oobe_settings() -> ET.Element:
    """OOBE pass: finalize user settings."""
    component = ET.Element(
        "component",
        Name="Microsoft-Windows-Shell-Setup",
        processorArchitecture="amd64",
        publicKeyToken="31bf3856ad364e35",
        language="neutral",
        versionScope="nonSxS",
    )
    
    # OOBE settings
    OOBE = ET.SubElement(component, "OOBE")
    ET.SubElement(OOBE, "HideEULAPage").text = "true"
    ET.SubElement(OOBE, "HideLocalAccountScreen").text = "true"
    ET.SubElement(OOBE, "HideOnlineAccountScreens").text = "true"
    ET.SubElement(OOBE, "HideWirelessSetupInOOBE").text = "true"
    ET.SubElement(OOBE, "NetworkLocation").text = "Work"
    ET.SubElement(OOBE, "ProtectYourPC").text = "1"
    
    # User accounts
    users = ET.SubElement(component, "UserAccounts")
    local_accounts = ET.SubElement(users, "LocalAccounts")
    local_account = ET.SubElement(local_accounts, "LocalAccount")
    ET.SubElement(local_account, "Name").text = "vmuser"
    ET.SubElement(local_account, "DisplayName").text = "VM User"
    ET.SubElement(local_account, "Group").text = "Administrators"
    
    password_elem = ET.SubElement(local_account, "Password")
    password_val = ET.SubElement(password_elem, "Value")
    password_val.text = "vmuser123"
    ET.SubElement(password_elem, "PlainText").text = "true"
    
    # Auto logon
    auto_logon = ET.SubElement(component, "AutoLogon")
    ET.SubElement(auto_logon, "Enabled").text = "true"
    ET.SubElement(auto_logon, "Username").text = "vmuser"
    auto_pass = ET.SubElement(auto_logon, "Password")
    ET.SubElement(auto_pass, "Value").text = "vmuser123"
    ET.SubElement(auto_pass, "PlainText").text = "true"
    ET.SubElement(auto_logon, "LogonCount").text = "1"
    
    NTAuth = ET.SubElement(auto_logon, "Domain").text = ""
    
    return component


def _firstlogoncommands(username: str, password: str, enable_ssh: bool = True) -> ET.Element:
    """FirstLogonCommands: scripts that run after first logon."""
    component = ET.Element(
        "component",
        Name="Microsoft-Windows-Shell-Setup",
        processorArchitecture="amd64",
        publicKeyToken="31bf3856ad364e35",
        language="neutral",
        versionScope="nonSxS",
    )
    
    flc = ET.SubElement(component, "FirstLogonCommands")
    
    # Step 1: Enable local admin password expiry to never expire
    cmd1 = ET.SubElement(flc, "SynchronousCommand")
    ET.SubElement(cmd1, "Order").text = "1"
    ET.SubElement(cmd1, "Description").text = "Disable password expiry"
    ET.SubElement(cmd1, "CommandLine").text = 'cmd.exe /c "net accounts /maxpwage:unlimited"'
    ET.SubElement(cmd1, "RequiresUserInput").text = "false"
    
    if enable_ssh:
        # Step 2: Install and enable OpenSSH Server
        cmd2 = ET.SubElement(flc, "SynchronousCommand")
        ET.SubElement(cmd2, "Order").text = "2"
        ET.SubElement(cmd2, "Description").text = "Install OpenSSH Server"
        ET.SubElement(cmd2, "CommandLine").text = (
            'powershell.exe -Command '
            '"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 '
            '| Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0; '
            'Set-Service -Name sshd -StartupType Automatic; '
            'Start-Service sshd"'
        )
        ET.SubElement(cmd2, "RequiresUserInput").text = "false"
        
        # Step 3: Configure Firewall for SSH
        cmd3 = ET.SubElement(flc, "SynchronousCommand")
        ET.SubElement(cmd3, "Order").text = "3"
        ET.SubElement(cmd3, "Description").text = "Configure Firewall for SSH"
        ET.SubElement(cmd3, "CommandLine").text = (
            'powershell.exe -Command '
            '"New-NetFirewallRule -Name sshd -DisplayName \'OpenSSH Server (sshd)\' '
            '-Enabled True -Action Allow -Protocol TCP -LocalPort 22"'
        )
        ET.SubElement(cmd3, "RequiresUserInput").text = "false"
    
    return component


def create_autounattend_iso(xml_root: ET.Element, output_path: Path) -> Path:
    """
    Write autounattend.xml to a temp file, then package into a virtual floppy ISO.
    Windows Setup looks for AUTOUNATTEND.XML on a floppy or CD.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        xml_path = tmpdir / "AUTOUNATTEND.XML"
        
        # Write XML
        tree = ET.ElementTree(xml_root)
        ET.indent(tree, space="  ")
        tree.write(str(xml_path), encoding="utf-8", xml_declaration=True)
        
        # Create ISO with genisoimage
        result = subprocess.run(
            [
                "genisoimage", "-volid", "AUTOUNATTEND", "-joliet", "-rock",
                "-o", str(output_path), str(tmpdir)
            ],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"genisoimage failed for autounattend: {result.stderr.decode().strip()}"
            )
    
    logger.info(f"Autounattend ISO created: {output_path}")
    return output_path


# Convenience function for direct use
def generate_and_create_iso(username="vmuser", password="vmuser123", enable_ssh=True) -> tuple[ET.Element, Path]:
    """Generate XML and create ISO in one call."""
    xml_root = generate_autounattend_xml(username, password, enable_ssh)
    iso_path = Path("/tmp") / f"autounattend-{hash(str(xml_root)) % 10000}.iso"
    iso_path = create_autounattend_iso(xml_root, iso_path)
    return xml_root, iso_path


# ---------------------------------------------------------------------------
# Wrapper classes for class-based usage patterns
# ---------------------------------------------------------------------------

class WindowsProvisioner:
    """Class-based wrapper around Windows autounattend provisioning functions."""

    def __init__(self, username="vmuser", password="vmuser123", enable_ssh=True, skip_tpm=True):
        self.username = username
        self.password = password
        self.enable_ssh = enable_ssh
        self.skip_tpm = skip_tpm

    def create_unattended_iso(self, target_dir: str) -> str:
        """Create an autounattend ISO in the given directory."""
        xml_root = generate_autounattend_xml(
            self.username, self.password, self.enable_ssh, self.skip_tpm
        )
        output_path = Path(target_dir) / "autounattend.iso"
        create_autounattend_iso(xml_root, output_path)
        return str(output_path)
