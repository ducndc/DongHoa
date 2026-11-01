#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Build the donghoa OpenWrt package with the official SDK, run inside Docker.
#
#   openwrt/build.sh [target/subtarget] [release]
#   openwrt/build.sh                      # x86/64 25.12.6 (QEMU test VMs)
#   openwrt/build.sh mediatek/filogic     # e.g. a Filogic router
#   openwrt/build.sh ramips/mt7621 24.10.8
#
# Downloads and checks the SDK on first use. Output: the path of the .apk
# (25.x) or .ipk (24.x) package.

set -e

TARGET=${1:-x86/64}
RELEASE=${2:-25.12.6}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$REPO/build/openwrt/sdk-$RELEASE-$(echo "$TARGET" | tr / -)
URL=https://downloads.openwrt.org/releases/$RELEASE/targets/$TARGET
IMAGE=openwrt-sdk-builder

if [ ! -d "$WORK/sdk" ]; then
	mkdir -p "$WORK"
	cd "$WORK"
	curl -sSfO "$URL/sha256sums"
	sdk=$(grep -oE 'openwrt-sdk-[^ ]+\.tar\.(zst|xz)$' sha256sums | head -1)
	[ -n "$sdk" ] || { echo "no SDK listed at $URL" >&2; exit 1; }
	echo "downloading $sdk"
	curl -sSfO "$URL/$sdk"
	grep " \*\?$sdk\$" sha256sums | sed 's/ \*/  /' | sha256sum -c
	mkdir sdk
	tar -xf "$sdk" -C sdk --strip-components=1
	rm "$sdk"
fi

docker image inspect "$IMAGE" >/dev/null 2>&1 ||
	docker build -q -t "$IMAGE" -f "$REPO/openwrt/sdk.Dockerfile" "$REPO/openwrt"

# Same path inside and outside the container, so the src-link feed resolves.
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
	-v "$REPO:$REPO" -w "$WORK/sdk" "$IMAGE" sh -ec "
	echo 'src-link donghoa $REPO/openwrt' > feeds.conf
	./scripts/feeds update donghoa >/dev/null
	./scripts/feeds install donghoa >/dev/null
	make defconfig >/dev/null 2>&1
	make package/donghoa/clean >/dev/null
	make package/donghoa/compile -j\$(nproc) || make package/donghoa/compile V=s
"
find "$WORK/sdk/bin/packages" -name 'donghoa*.[ai]pk'
