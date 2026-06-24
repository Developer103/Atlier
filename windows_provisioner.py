"""
Windows VM Provisioner using autounattend.xml.
- Generates autounattend.xml that automates the entire Windows installation
- Handles partitioning, OOBE bypass, TPM bypass, SSH setup
"""

import logging
import struct
from pathlib import Path


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EFI shell startup script — searches all FSn mounts for the Windows bootloader
# ---------------------------------------------------------------------------
# OVMF has no ISO9660 driver, so it can't read the autounattend ISO9660 disk.
# By creating the autounattend "disk" as a raw FAT12 image, OVMF's FatDxe will
# mount it as FSn.  The EFI Shell then finds startup.nsh there and runs it,
# which locates and launches the Windows installer EFI binary on another FSn.
#
# Windows Setup (in WindowsPE) enumerates all drives including ATAPI CD-ROMs
# that contain FAT, so AUTOUNATTEND.XML on this disk will be found too.

_STARTUP_NSH = """\
# & exit /b
@echo -off
connect -r
map -r
fs0:\\EFI\\Microsoft\\Boot\\bootmgfw.efi
fs1:\\EFI\\Microsoft\\Boot\\bootmgfw.efi
fs2:\\EFI\\Microsoft\\Boot\\bootmgfw.efi
fs3:\\EFI\\Microsoft\\Boot\\bootmgfw.efi
fs4:\\EFI\\Microsoft\\Boot\\bootmgfw.efi
"""

# ---------------------------------------------------------------------------
# Autounattend XML template
# ---------------------------------------------------------------------------
# Uses a plain string template instead of xml.etree because ElementTree can't
# emit wcm: namespace attributes, which Windows Setup requires on collection
# elements (Disk, CreatePartition, LocalAccount, SynchronousCommand, etc.)
# Without wcm:action="add", Windows silently ignores those elements.

_AUTOUNATTEND_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

  <!-- WindowsPE pass: TPM bypass, disk setup, product key -->
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <UILanguage>en-US</UILanguage>
      <SystemLocale>en-US</SystemLocale>
      <UserLocale>en-US</UserLocale>
      <UILanguageFallback>en-US</UILanguageFallback>
      <InputLocale>en-US</InputLocale>
    </component>

    <component name="Microsoft-Windows-Setup"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">

      <!-- Bypass Windows 11 hardware checks before setup validates requirements -->
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassTPMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassSecureBootCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassRAMCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>4</Order>
          <Path>reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassCPUCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
        <RunSynchronousCommand wcm:action="add">
          <Order>5</Order>
          <Path>reg add "HKLM\\SYSTEM\\Setup\\LabConfig" /v BypassStorageCheck /t REG_DWORD /d 1 /f</Path>
        </RunSynchronousCommand>
      </RunSynchronous>

      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>EFI</Type>
              <Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order>
              <Type>MSR</Type>
              <Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>FAT32</Format>
              <Label>SYSTEM</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order>
              <PartitionID>2</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order>
              <PartitionID>3</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>

      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/NAME</Key>
              <Value>Windows 11 Pro</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>3</PartitionID>
          </InstallTo>
          <WillShowUI>Never</WillShowUI>
        </OSImage>
      </ImageInstall>

      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>Analyst</FullName>
        <Organization>Security Team</Organization>
        <ProductKey>
          <Key>W269N-WFGWX-YVC9B-4J6C9-T83GX</Key>
          <WillShowUI>Never</WillShowUI>
        </ProductKey>
      </UserData>

    </component>
  </settings>

  <!-- Specialize pass: computer name -->
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>MalwareVM</ComputerName>
    </component>
  </settings>

  <!-- OOBE pass: create user, configure autologon, install SSH -->
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">

      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>

      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>{username}</Name>
            <DisplayName>VM User</DisplayName>
            <Group>Administrators</Group>
            <Password>
              <Value>{password}</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>

      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>{username}</Username>
        <Password>
          <Value>{password}</Value>
          <PlainText>true</PlainText>
        </Password>
        <LogonCount>5</LogonCount>
      </AutoLogon>

      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Description>Disable password expiry</Description>
          <CommandLine>net accounts /maxpwage:unlimited</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Description>Install and start OpenSSH Server</Description>
          <CommandLine>powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Set-Service sshd -StartupType Automatic; Start-Service sshd; New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue"</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
      </FirstLogonCommands>

    </component>
  </settings>

</unattend>
"""


# ---------------------------------------------------------------------------
# Pure-Python FAT12 disk image builder with subdirectory support
# ---------------------------------------------------------------------------

def _fat12_lfn_checksum(name83: bytes) -> int:
    s = 0
    for b in name83:
        s = (((s & 1) << 7) | (s >> 1)) + b & 0xFF
    return s


def _lfn_entries(long_name: str, short11: bytes) -> bytes:
    cksum = _fat12_lfn_checksum(short11)
    ucs2 = long_name.encode("utf-16-le") + b"\x00\x00"
    while (len(ucs2) // 2) % 13 != 0:
        ucs2 += b"\xff\xff"
    n = len(ucs2) // 26
    out = bytearray()
    for i in range(n - 1, -1, -1):
        chunk = ucs2[i * 26 : (i + 1) * 26]
        e = bytearray(32)
        e[0]      = (i + 1) | (0x40 if i == n - 1 else 0)
        e[1:11]   = chunk[0:10]
        e[11]     = 0x0F
        e[13]     = cksum
        e[14:26]  = chunk[10:22]
        e[28:32]  = chunk[22:26]
        out.extend(e)
    return bytes(out)


def _short11(long_name: str) -> bytes:
    nm = long_name.upper()
    base, ext = (nm.rsplit(".", 1) if "." in nm else (nm, ""))
    b8 = ((base[:6] + "~1") if len(base) > 8 else base).ljust(8)[:8]
    e3 = ext[:3].ljust(3)
    return (b8 + e3).encode("ascii")


def _make_file_entry(long_name: str, start_cluster: int, file_size: int) -> bytes:
    s11 = _short11(long_name)
    lfn = _lfn_entries(long_name, s11)
    entry = bytearray(32)
    entry[0:11]  = s11
    entry[11]    = 0x20                         # ATTR_ARCHIVE
    entry[26:28] = struct.pack("<H", start_cluster)
    entry[28:32] = struct.pack("<I", file_size)
    return lfn + bytes(entry)


def _make_subdir_entry(long_name: str, start_cluster: int) -> bytes:
    s11 = _short11(long_name)
    lfn = _lfn_entries(long_name, s11)
    entry = bytearray(32)
    entry[0:11]  = s11
    entry[11]    = 0x10                         # ATTR_DIRECTORY
    entry[26:28] = struct.pack("<H", start_cluster)
    return lfn + bytes(entry)


def _build_fat12_image(files: dict, size_mb: int = 4) -> bytes:
    """Build a FAT12 raw disk image with subdirectory support.

    files     : {path_str: content_bytes}  path uses '/' separator, e.g.
                "EFI/BOOT/BOOTX64.EFI" or "AUTOUNATTEND.XML"
    size_mb   : disk size in MiB
    """
    SECTOR        = 512
    CLUSTER_SECS  = 4          # 2 KiB per cluster
    NUM_FATS      = 2
    ROOT_ENTRIES  = 128
    TOTAL_SECS    = size_mb * 1024 * 1024 // SECTOR
    ROOT_DIR_SECS = ROOT_ENTRIES * 32 // SECTOR
    CLUSTER_BYTES = CLUSTER_SECS * SECTOR

    FAT_SECS = 3
    for _ in range(6):
        data_start = 1 + NUM_FATS * FAT_SECS + ROOT_DIR_SECS
        n_clust    = (TOTAL_SECS - data_start) // CLUSTER_SECS
        FAT_SECS   = max(1, (n_clust * 3 // 2 + SECTOR - 1) // SECTOR)

    DATA_START_SEC = 1 + NUM_FATS * FAT_SECS + ROOT_DIR_SECS

    image = bytearray(TOTAL_SECS * SECTOR)
    fat   = bytearray(FAT_SECS * SECTOR)
    fat[0] = 0xF8; fat[1] = 0xFF; fat[2] = 0xFF

    _nc = [2]  # next_cluster (list for closure mutation)

    def fat12_set(c: int, v: int) -> None:
        off = c * 3 // 2
        if c % 2 == 0:
            fat[off]     = v & 0xFF
            fat[off + 1] = (fat[off + 1] & 0xF0) | ((v >> 8) & 0x0F)
        else:
            fat[off]     = (fat[off] & 0x0F) | ((v & 0x0F) << 4)
            fat[off + 1] = (v >> 4) & 0xFF

    def alloc_clusters(n: int) -> list:
        cs = list(range(_nc[0], _nc[0] + n))
        _nc[0] += n
        for i, c in enumerate(cs):
            fat12_set(c, cs[i + 1] if i < n - 1 else 0xFFF)
        return cs

    def clusters_needed(size: int) -> int:
        return max(1, -(-size // CLUSTER_BYTES))

    def write_data(clusters: list, data: bytes) -> None:
        for i, c in enumerate(clusters):
            off = (DATA_START_SEC + (c - 2) * CLUSTER_SECS) * SECTOR
            chunk = data[i * CLUSTER_BYTES : (i + 1) * CLUSTER_BYTES]
            image[off : off + len(chunk)] = chunk

    # Build directory tree from flat path dict
    # tree: dict mapping dir_path_tuple → {name: ("file", data) | ("dir", {})}
    tree: dict = {}  # top-level entries

    def get_or_create_dir(parts):
        node = tree
        for p in parts:
            pk = p.upper()
            if pk not in node:
                node[pk] = ("dir", {}, p)  # (type, children, original_name)
            node = node[pk][1]
        return node

    for path_str, data in files.items():
        parts = path_str.replace("\\", "/").split("/")
        if len(parts) == 1:
            tree[parts[0].upper()] = ("file", data, parts[0])
        else:
            dir_node = get_or_create_dir(parts[:-1])
            fname = parts[-1]
            dir_node[fname.upper()] = ("file", data, fname)

    # First pass: allocate clusters for all files and directories (BFS)
    # We need to know cluster numbers before writing directory entries
    # Process: assign clusters to dirs, then build their content and write

    def assign_and_write(node: dict, parent_cluster: int, is_root: bool) -> tuple:
        """Return (dir_entries_bytes, own_cluster) for this directory node.

        For the root directory, we write directly to the fixed root area.
        For subdirectories, we allocate a cluster, write dot/dotdot + entries.
        """
        entries_bytes = bytearray()

        # Sort: dirs first, then files (nice to have, not required)
        items = sorted(node.items(), key=lambda kv: 0 if kv[1][0] == "dir" else 1)

        for _key, item in items:
            kind, payload, orig_name = item
            if kind == "file":
                data = payload
                n = clusters_needed(len(data))
                cs = alloc_clusters(n)
                write_data(cs, data)
                entries_bytes += _make_file_entry(orig_name, cs[0], len(data))
            else:  # dir
                children = payload
                # Allocate cluster for this subdirectory NOW so we know it
                dir_cs = alloc_clusters(1)
                dir_cluster = dir_cs[0]
                # Recurse
                sub_entries, _ = assign_and_write(children, dir_cluster, False)
                # Prepend . and ..
                dot = bytearray(32)
                dot[0:11] = b".          "; dot[11] = 0x10
                dot[26:28] = struct.pack("<H", dir_cluster)
                dotdot = bytearray(32)
                dotdot[0:11] = b"..         "; dotdot[11] = 0x10
                dotdot[26:28] = struct.pack("<H", parent_cluster)
                full_dir_content = bytes(dot) + bytes(dotdot) + sub_entries
                # Expand to multiple clusters if needed
                extra = clusters_needed(len(full_dir_content)) - 1
                if extra > 0:
                    extra_cs = alloc_clusters(extra)
                    fat12_set(dir_cs[-1], extra_cs[0])
                    fat12_set(dir_cs[-1], extra_cs[0])
                    dir_cs += extra_cs
                    for i in range(len(dir_cs) - 1):
                        fat12_set(dir_cs[i], dir_cs[i + 1])
                    fat12_set(dir_cs[-1], 0xFFF)
                write_data(dir_cs, full_dir_content)
                entries_bytes += _make_subdir_entry(orig_name, dir_cluster)

        return bytes(entries_bytes), parent_cluster

    root_entries_bytes, _ = assign_and_write(tree, 0, True)

    # Write root directory
    root_off = (1 + NUM_FATS * FAT_SECS) * SECTOR
    if len(root_entries_bytes) > ROOT_ENTRIES * 32:
        raise RuntimeError("Root directory full — increase ROOT_ENTRIES")
    image[root_off : root_off + len(root_entries_bytes)] = root_entries_bytes

    # Write FAT copies
    for i in range(NUM_FATS):
        off = (1 + i * FAT_SECS) * SECTOR
        image[off : off + FAT_SECS * SECTOR] = fat

    # BPB
    bs = bytearray(SECTOR)
    bs[0:3]   = b"\xeb\x3c\x90"
    bs[3:11]  = b"MSWIN4.1"
    struct.pack_into("<H", bs, 11, SECTOR)
    bs[13]    = CLUSTER_SECS
    struct.pack_into("<H", bs, 14, 1)
    bs[16]    = NUM_FATS
    struct.pack_into("<H", bs, 17, ROOT_ENTRIES)
    struct.pack_into("<H", bs, 19, TOTAL_SECS if TOTAL_SECS <= 0xFFFF else 0)
    struct.pack_into("<I", bs, 32, TOTAL_SECS if TOTAL_SECS > 0xFFFF else 0)
    bs[21]    = 0xF8
    struct.pack_into("<H", bs, 22, FAT_SECS)
    struct.pack_into("<H", bs, 24, 63)
    struct.pack_into("<H", bs, 26, 255)
    bs[36]    = 0x00
    bs[38]    = 0x29
    struct.pack_into("<I", bs, 39, 0x12345678)
    bs[43:54] = b"WINBOOT    "
    bs[54:62] = b"FAT12   "
    bs[510]   = 0x55
    bs[511]   = 0xAA
    image[:SECTOR] = bs

    return bytes(image)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_autounattend_xml(
    username: str = "vmuser",
    password: str = "vmuser123",
    enable_ssh: bool = True,
    skip_tpm: bool = True,
) -> str:
    """Return autounattend.xml as a string, ready to write to disk."""
    return _AUTOUNATTEND_TEMPLATE.format(username=username, password=password)



def create_autounattend_iso(
    xml_content: str,
    output_path: Path,
) -> Path:
    """Create the autounattend disk image that QEMU exposes as an ATAPI CD-ROM.

    The disk is a raw FAT12 image containing only AUTOUNATTEND.XML and
    startup.nsh.  BOOTX64.EFI/BCD are intentionally NOT embedded.

    Boot flow:
      OVMF BDS → Boot0001 (Windows ISO/Sata(0x1)) times out scanning ISO9660
               → Boot0003 (our FAT disk/Sata(0x3)) "Not Found" — no BOOTX64.EFI
               → EFI Shell finds startup.nsh on our FAT disk and runs it
               → startup.nsh executes FS1:\\EFI\\BOOT\\BOOTX64.EFI
                  (the Windows ISO's El Torito EFI FAT partition = VenMedia)
               → WBM is loaded with the VenMedia partition as its device handle
               → WBM finds BCD on the same VenMedia partition and boots Windows PE

    Embedding BOOTX64.EFI on our raw FAT disk causes WBM to load with
    Sata(0x3) as its device.  WBM only searches for BCD on GPT EFI System
    Partitions; a raw FAT12 disk has no GPT/ESP marker, so BCD is never
    found (STATUS_NO_SUCH_FILE 0xc000000f).  Running WBM from the VenMedia
    partition avoids this because that partition IS recognised as an ESP.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    files: dict = {
        "AUTOUNATTEND.XML": xml_content.encode("utf-8"),
        "startup.nsh":      _STARTUP_NSH.encode("utf-8"),
    }
    image_bytes = _build_fat12_image(files, size_mb=4)
    output_path.write_bytes(image_bytes)
    logger.info(
        "Autounattend FAT12 disk created: %s (%d KiB, startup.nsh + AUTOUNATTEND.XML)",
        output_path, len(image_bytes) // 1024,
    )
    return output_path


# ---------------------------------------------------------------------------
# Wrapper class for class-based usage patterns
# ---------------------------------------------------------------------------

class WindowsProvisioner:
    def __init__(self, username="vmuser", password="vmuser123", enable_ssh=True, skip_tpm=True):
        self.username = username
        self.password = password
        self.enable_ssh = enable_ssh
        self.skip_tpm = skip_tpm

    def create_unattended_iso(self, target_dir: str) -> str:
        xml = generate_autounattend_xml(self.username, self.password, self.enable_ssh, self.skip_tpm)
        output_path = Path(target_dir) / "autounattend.iso"
        create_autounattend_iso(xml, output_path)
        return str(output_path)
