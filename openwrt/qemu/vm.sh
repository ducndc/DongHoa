#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Run OpenWrt x86-64 test APs under QEMU/KVM, no root needed.
#
#   vm.sh start <n>   boot AP n (1..9) in the background
#   vm.sh stop <n>
#   vm.sh ssh <n> [cmd]
#   vm.sh console <n> print the serial console log
#
# Per AP:
#   eth0 (br-lan, 192.168.1.1)  QEMU user net: ssh on 127.0.0.1:222<n>,
#                               NAT to the internet for apk.
#   eth1                        shared backhaul segment between all APs
#                               (UDP multicast on loopback). ARCP runs here.
#
# Disk: a qcow2 overlay per AP on top of $WORK/base.img, the
# x86-64 generic-ext4-combined image, downloaded on first start.
# Delete build/openwrt/vm/ap<n>.qcow2 to reset an AP.

set -e

WORK=${DONGHOA_VM_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/build/openwrt/vm}
RELEASE=${DONGHOA_VM_RELEASE:-25.12.6}
BH_MCAST=${DONGHOA_VM_MCAST:-230.0.0.1:23456}
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"

cmd=$1
n=$2
[ -n "$cmd" ] && [ -n "$n" ] || { sed -n '4,10p' "$0"; exit 1; }
case "$n" in [1-9]) ;; *) echo "AP number must be 1..9" >&2; exit 1 ;; esac

disk=$WORK/ap$n.qcow2
pidf=$WORK/ap$n.pid
port=$((2220 + n))

case "$cmd" in
start)
	if [ ! -f "$WORK/base.img" ]; then
		url=https://downloads.openwrt.org/releases/$RELEASE/targets/x86/64
		img=openwrt-$RELEASE-x86-64-generic-ext4-combined.img.gz
		mkdir -p "$WORK"
		(cd "$WORK" && curl -sSfO "$url/sha256sums" && curl -sSfO "$url/$img" &&
		 grep " \*\?$img\$" sha256sums | sed 's/ \*/  /' | sha256sum -c) || exit 1
		# gzip warns about the trailing signature block: not an error.
		gunzip -c "$WORK/$img" > "$WORK/base.img" 2>/dev/null || true
	fi
	[ -f "$disk" ] || qemu-img create -q -f qcow2 -b base.img -F raw "$disk" 512M
	qemu-system-x86_64 -name ap$n -enable-kvm -cpu host -smp 2 -m 256 \
		-drive file="$disk",if=virtio \
		-netdev user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dns=192.168.1.3,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:$port-192.168.1.1:22 \
		-device virtio-net-pci,netdev=lan,mac=52:54:00:00:0$n:01 \
		-netdev socket,id=bh,mcast=$BH_MCAST,localaddr=127.0.0.1 \
		-device virtio-net-pci,netdev=bh,mac=52:54:00:00:0$n:02 \
		-display none -serial file:"$WORK/ap$n.console" \
		-daemonize -pidfile "$pidf"
	echo "ap$n started, ssh: $0 ssh $n"
	;;
stop)
	[ -f "$pidf" ] && kill "$(cat "$pidf")" 2>/dev/null || true
	rm -f "$pidf"
	;;
ssh)
	shift 2
	# Fresh OpenWrt has no root password; dropbear lets root in.
	exec ssh $SSH_OPTS -p "$port" root@127.0.0.1 "$@"
	;;
console)
	cat "$WORK/ap$n.console"
	;;
*)
	sed -n '4,10p' "$0"; exit 1
	;;
esac
