#!/bin/bash
# VM snapshot management via QMP blockdev-snapshot-sync
# Usage:
#   ./scripts/vm_snapshot.sh save [name]     — create overlay snapshot
#   ./scripts/vm_snapshot.sh restore [name]  — discard overlay, reboot from base
#   ./scripts/vm_snapshot.sh list            — show available snapshots
#
# NEVER uses savevm/loadvm — those crash UEFI pflash.

QMP_SOCK="${QMP_SOCK:-/tmp/vm_provision/vm-windows-11.qmp}"
DISK_IMG="${DISK_IMG:-/tmp/vm_provision/base_windows-11.cow.qcow2}"
DISK_DEVICE="${DISK_DEVICE:-ide0-hd0}"
VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"

DISK_DIR="$(dirname "$DISK_IMG")"
DISK_STEM="$(basename "$DISK_IMG" .qcow2)"

qmp_cmd() {
    local cmd="$1"
    (echo '{"execute":"qmp_capabilities"}'; sleep 0.3; echo "$cmd"; sleep 0.5) \
        | socat - UNIX-CONNECT:"$QMP_SOCK" 2>/dev/null | tail -1
}

wait_ssh() {
    local timeout="${1:-120}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if sshpass -p "$VM_PASS" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
            -p "$VM_PORT" "$VM_USER@localhost" "echo ok" >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    return 1
}

case "${1:-help}" in
    save)
        TAG="${2:-clean_state}"
        OVERLAY="$DISK_DIR/${DISK_STEM}.overlay-${TAG}.qcow2"

        # SAFETY: verify base disk exists before snapshotting.
        # If the base is gone (deleted while QEMU held fd), the overlay
        # will have a dangling backing-file reference and restore will fail.
        if [ ! -f "$DISK_IMG" ]; then
            echo "WARNING: base disk missing: $DISK_IMG"
            echo "  QEMU may be running from a deleted file (fd still open)."
            echo "  Attempting to recover base disk via QMP block commit..."
            # Try to get QEMU to flush its in-memory state to a new file
            qemu-img create -f qcow2 "$DISK_IMG" 80G 2>/dev/null
            RESULT=$(qmp_cmd "{\"execute\":\"block-commit\",\"arguments\":{\"device\":\"$DISK_DEVICE\"}}")
            if ! echo "$RESULT" | grep -q '"return"'; then
                rm -f "$DISK_IMG"
                echo "ABORT: cannot recover base disk. Save a full snapshot instead:"
                echo "  qemu-img convert from the running device"
                exit 1
            fi
            echo "  Base disk recovered."
        fi

        rm -f "$OVERLAY"
        echo "Creating snapshot '$TAG'..."
        RESULT=$(qmp_cmd "{\"execute\":\"blockdev-snapshot-sync\",\"arguments\":{\"device\":\"$DISK_DEVICE\",\"snapshot-file\":\"$OVERLAY\",\"format\":\"qcow2\"}}")
        if echo "$RESULT" | grep -q '"return"'; then
            echo "OK — overlay: $OVERLAY"
            echo "  All writes now go to the overlay."
            echo "  Use '$0 restore $TAG' to revert."
        else
            echo "FAILED: $RESULT"
            exit 1
        fi
        ;;

    restore)
        TAG="${2:-clean_state}"
        OVERLAY="$DISK_DIR/${DISK_STEM}.overlay-${TAG}.qcow2"
        if [ ! -f "$OVERLAY" ]; then
            echo "No snapshot '$TAG' found (expected $OVERLAY)"
            exit 1
        fi

        # SAFETY: verify base disk exists BEFORE touching anything.
        # The overlay is the ONLY copy of post-snapshot writes. If the
        # base disk is gone and we delete the overlay, the VM is bricked.
        if [ ! -f "$DISK_IMG" ]; then
            echo "ABORT: base disk missing: $DISK_IMG"
            echo "  The overlay ($OVERLAY) is the only surviving disk."
            echo "  Committing overlay into a standalone base disk..."
            qemu-img convert -O qcow2 "$OVERLAY" "$DISK_IMG"
            if [ $? -ne 0 ] || [ ! -f "$DISK_IMG" ]; then
                echo "  FAILED to commit overlay. Overlay preserved, nothing deleted."
                exit 1
            fi
            echo "  Base disk recovered from overlay ($(du -h "$DISK_IMG" | cut -f1))."
        fi

        echo "Restoring snapshot '$TAG'..."

        # 1. Graceful shutdown via SSH
        echo "  Shutting down VM..."
        sshpass -p "$VM_PASS" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            -p "$VM_PORT" "$VM_USER@localhost" "shutdown /s /t 0" >/dev/null 2>&1 || true

        # 2. Wait for QEMU to exit (or force after 30s)
        QEMU_PID=$(pgrep -f "qmp.*$QMP_SOCK" || true)
        if [ -n "$QEMU_PID" ]; then
            echo "  Waiting for QEMU (PID $QEMU_PID) to exit..."
            for i in $(seq 1 30); do
                if ! kill -0 "$QEMU_PID" 2>/dev/null; then break; fi
                sleep 1
            done
            if kill -0 "$QEMU_PID" 2>/dev/null; then
                echo "  Force killing QEMU..."
                kill -9 "$QEMU_PID" 2>/dev/null
                sleep 2
            fi
        fi

        # 3. Verify base disk is still intact after QEMU exit
        if [ ! -f "$DISK_IMG" ]; then
            echo "ABORT: base disk vanished after QEMU shutdown: $DISK_IMG"
            echo "  This can happen if the COW was deleted while QEMU held the fd."
            echo "  Overlay preserved: $OVERLAY"
            exit 1
        fi

        # 4. Discard overlay
        echo "  Discarding overlay..."
        rm -f "$OVERLAY"
        rm -f "$QMP_SOCK"

        # 4. Reboot QEMU (re-use the command line from /proc)
        echo "  Rebooting VM from base disk..."
        # Restart swtpm if present
        TPM_SOCK="/tmp/vm_provision/vm-windows-11-tpm.sock"
        TPM_STATE="/tmp/vm_provision/vm-windows-11-tpm"
        if [ -d "$TPM_STATE" ]; then
            pkill -f "swtpm.*$TPM_SOCK" 2>/dev/null || true
            sleep 1
            rm -f "$TPM_SOCK"
            swtpm socket --tpmstate dir="$TPM_STATE" --ctrl type=unixio,path="$TPM_SOCK" \
                --tpm2 --log level=0 &
            sleep 1
        fi

        qemu-system-x86_64 -enable-kvm -name vm-windows-11 -m 8192 -cpu host -smp cores=4 \
            -machine q35,accel=kvm \
            -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
            -drive if=pflash,format=raw,file=/tmp/vm_provision/OVMF_VARS_4M.fd \
            -drive if=ide,index=0,file="$DISK_IMG",format=qcow2,cache=none \
            -chardev socket,id=chrtpm,path="$TPM_SOCK" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-tis,tpmdev=tpm0 \
            -qmp "unix:$QMP_SOCK,server,nowait" \
            -netdev user,id=net0,hostfwd=tcp::${VM_PORT}-:22,hostfwd=tcp::13389-:3389 \
            -device e1000,netdev=net0,romfile= \
            -vga std -vnc 127.0.0.1:1 \
            -serial file:/tmp/vm.log \
            -daemonize

        # 5. Wait for SSH
        echo "  Waiting for SSH..."
        if wait_ssh 120; then
            echo "OK — VM restored to '$TAG' state."
        else
            echo "WARNING — VM booted but SSH not ready after 120s"
            exit 1
        fi
        ;;

    list)
        echo "Available snapshots:"
        found=0
        for f in "$DISK_DIR"/${DISK_STEM}.overlay-*.qcow2; do
            if [ -f "$f" ]; then
                TAG=$(echo "$f" | sed "s|.*overlay-||; s|\.qcow2$||")
                SIZE=$(du -h "$f" | cut -f1)
                echo "  $TAG  ($SIZE)  $f"
                found=1
            fi
        done
        if [ "$found" = "0" ]; then
            echo "  (none)"
        fi
        ;;

    help|*)
        echo "Usage: $0 {save|restore|list} [snapshot_name]"
        echo ""
        echo "  save [name]     Create overlay snapshot (default: clean_state)"
        echo "  restore [name]  Discard overlay and reboot from base (default: clean_state)"
        echo "  list            Show available snapshots"
        echo ""
        echo "Environment:"
        echo "  QMP_SOCK=$QMP_SOCK"
        echo "  DISK_IMG=$DISK_IMG"
        echo "  DISK_DEVICE=$DISK_DEVICE"
        ;;
esac
