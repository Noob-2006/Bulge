#!/usr/bin/env bash
# Boot a built guest image under QEMU and wait for the guest agent to come up.
#
#   packaging/vm/smoke-boot.sh IMAGE_DIR x86_64|aarch64 disk|direct [TIMEOUT_SECS]
#
# disk   : UEFI firmware (OVMF / QEMU_EFI) boots IMAGE_DIR/disk.raw, exactly what
#          VirtualBox / Hyper-V do: no -kernel, no -append. The console is COM1
#          and the channel COM2 (ttyS1), each written to a file. Passes when the
#          agent logs "hello sent" (x86_64) — i.e. it opened /dev/ttyS1 from the
#          baked command line and wrote its Hello frame there. On aarch64 `virt`
#          has a single PL011 and no ttyS1, so the check is that the agent ran
#          as PID 1 from the embedded initramfs (any "seagent-vm-guest:" line).
# direct : -kernel vmlinux -initrd initramfs.cpio.gz with a virtio-serial-pci
#          port, as the QEMU provider (and, for the PCI part, vfkit) boot it.
#          Passes on "hello sent".
#
# Needs qemu-system-x86_64 + OVMF, or qemu-system-aarch64 + qemu-efi-aarch64.
# Uses KVM when /dev/kvm is usable, TCG otherwise. Writes only to a mktemp dir.
set -euo pipefail

[ $# -ge 3 ] || {
	sed -n '2,20p' "$0" >&2
	exit 2
}
IMG="$(cd -- "$1" && pwd)"
ARCH="$2"
MODE="$3"
TIMEOUT="${4:-300}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/seagent-smoke.XXXXXX")"
trap 'kill "${QPID:-0}" 2>/dev/null || true; rm -rf -- "$WORK"' EXIT

accel=tcg
if [ -r /dev/kvm ] && [ -w /dev/kvm ] && [ "$(uname -m)" = "$ARCH" ]; then accel=kvm; fi

firmware() {
	local f
	for f in "$@"; do
		[ -f "$f" ] && {
			printf '%s\n' "$f"
			return 0
		}
	done
	echo "no UEFI firmware found (tried: $*)" >&2
	exit 1
}

args=(-m 512 -smp 2 -display none -nodefaults -no-reboot -net none)
case "$ARCH" in
x86_64)
	QEMU=qemu-system-x86_64
	args+=(-machine q35 -accel "$accel")
	[ "$accel" = kvm ] && args+=(-cpu host) || args+=(-cpu max)
	console=ttyS0
	;;
aarch64)
	QEMU=qemu-system-aarch64
	args+=(-machine virt,highmem=on -accel "$accel")
	[ "$accel" = kvm ] && args+=(-cpu host) || args+=(-cpu max)
	console=ttyAMA0
	;;
*) echo "arch $ARCH: x86_64 or aarch64" >&2; exit 2 ;;
esac

want="hello sent"
case "$MODE" in
disk)
	if [ "$ARCH" = x86_64 ]; then
		code="$(firmware /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.4m.fd)"
		vars="$(firmware /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/x64/OVMF_VARS.4m.fd)"
		cp -- "$vars" "$WORK/vars.fd"
		args+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" -drive "if=pflash,format=raw,unit=1,file=$WORK/vars.fd")
		# COM1 = console, COM2 = the channel (what VirtualBox's --uart1/--uart2 give).
		args+=(-serial "file:$WORK/console.log" -serial "file:$WORK/chan.bin")
	else
		args+=(-bios "$(firmware /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd /usr/share/edk2/aarch64/QEMU_EFI.fd)")
		args+=(-serial "file:$WORK/console.log")
		want="seagent-vm-guest:"
	fi
	args+=(-drive "file=$IMG/disk.raw,format=raw,if=virtio,readonly=on")
	;;
direct)
	args+=(-kernel "$IMG/vmlinux" -initrd "$IMG/initramfs.cpio.gz")
	args+=(-append "console=$console rdinit=/sbin/init seagent.vm=smoke seagent.tier=ci seagent.channel=virtio-serial seagent.workspace=/workspace")
	args+=(-serial "file:$WORK/console.log")
	args+=(-chardev "file,id=c0,path=$WORK/chan.bin" -device virtio-serial-pci -device "virtserialport,chardev=c0,name=seagent0")
	;;
*) echo "mode $MODE: disk or direct" >&2; exit 2 ;;
esac

echo "smoke-boot: $QEMU (${accel}) $MODE $IMG" >&2
"$QEMU" "${args[@]}" &
QPID=$!
deadline=$((SECONDS + TIMEOUT))
while [ $SECONDS -lt $deadline ]; do
	if grep -q -- "$want" "$WORK/console.log" 2>/dev/null; then
		cat "$WORK/console.log" >&2
		if [ "$want" = "hello sent" ] && [ ! -s "$WORK/chan.bin" ]; then
			echo "smoke-boot: FAIL: the agent says it sent Hello but the channel is empty" >&2
			exit 1
		fi
		echo "smoke-boot: OK ($want)" >&2
		exit 0
	fi
	if ! kill -0 "$QPID" 2>/dev/null; then
		break
	fi
	sleep 2
done
echo "smoke-boot: FAIL: no '$want' within ${TIMEOUT}s; console:" >&2
cat "$WORK/console.log" >&2 2>/dev/null || true
exit 1
