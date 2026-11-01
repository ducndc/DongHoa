#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Turn a freshly booted test VM (vm.sh start <n>) into an ARCP test AP:
#   - internet via the QEMU NAT, eth1 left as a plain backhaul link
#   - mac80211_hwsim with 3 radios: ap-2g (ch 1), ap-5g (ch 36), radio2
#     spare for a test STA; SSID ARCP-TEST, FT-PSK (MD a1b2), 11k, 11v
#   - the donghoa package, configured for eth1; its BSSes come from
#     /etc/config/wireless (no bss lines in /etc/donghoa.conf)
#
#   provision.sh <n> <donghoa .apk>
#
# hwsim radios in different VMs cannot hear each other: roaming between VMs
# is not possible, steering between the two BSSes of one VM is.

set -e

n=$1
apk=$2
[ -n "$n" ] && [ -f "$apk" ] || { sed -n '4,13p' "$0"; exit 1; }
vm="$(dirname "$0")/vm.sh"

wait_ssh() {
	for i in $(seq 1 60); do
		"$vm" ssh "$n" true 2>/dev/null && return 0
		sleep 2
	done
	echo "ap$n: no ssh" >&2
	exit 1
}

# ---- phase 1: network and packages, then reboot ----
# Swapping wpad variants also reinstalls the wifi scripts, which a running
# netifd does not pick up: "wifi" then fails with "Not found".
wait_ssh
"$vm" ssh "$n" 'cat > /tmp/donghoa.apk' < "$apk"
"$vm" ssh "$n" sh -es <<EOF
uci set system.@system[0].hostname=ap$n
uci set network.lan.gateway=192.168.1.2
uci -q del_list network.lan.dns=192.168.1.3 || true
uci add_list network.lan.dns=192.168.1.3
uci set network.wan.proto=none
uci -q delete network.wan6 || true
uci commit
/etc/init.d/network reload
sleep 5

apk update >/dev/null
apk del wpad-basic-mbedtls >/dev/null 2>&1 || true
apk add kmod-mac80211-hwsim wpad-mbedtls iw >/dev/null
apk add --allow-untrusted /tmp/donghoa.apk >/dev/null
# kmodloader honours module options here at boot.
echo 'mac80211_hwsim radios=3' > \$(ls /etc/modules.d/*hwsim*)
/etc/init.d/wpad enable
rm -f /etc/config/wireless
reboot
EOF
sleep 10
wait_ssh

# ---- phase 2: wireless and donghoa ----
"$vm" ssh "$n" sh -es <<EOF
wifi config >/dev/null
for r in 0 1 2; do
	# hostapd refuses country 00 (802.11d), on any radio of the phy set.
	uci set wireless.radio\$r.country=US
done
for r in 0 1; do
	s=wireless.default_radio\$r
	uci set wireless.radio\$r.disabled=0
	uci set wireless.radio\$r.htmode=HT20
	uci set \$s.disabled=0
	uci set \$s.ssid=ARCP-TEST
	uci set \$s.encryption=psk2+ccmp
	uci set \$s.key=testpassphrase
	uci set \$s.ieee80211r=1
	uci set \$s.mobility_domain=a1b2
	uci set \$s.ft_over_ds=0
	uci set \$s.ft_psk_generate_local=1
	uci set \$s.ieee80211k=1
	uci set \$s.bss_transition=1
	uci set \$s.maxassoc=64
	# hwsim gives every VM the same MACs: make BSSIDs unique per AP.
	uci set \$s.macaddr=02:a1:00:00:0$n:0\$r
done
uci set wireless.radio0.band=2g
uci set wireless.radio0.channel=1
uci set wireless.default_radio0.ifname=ap-2g
uci set wireless.radio1.band=5g
uci set wireless.radio1.channel=36
uci set wireless.default_radio1.ifname=ap-5g
uci set wireless.radio2.disabled=1
uci set wireless.default_radio2.disabled=1
uci commit wireless
# "wifi" can print "Command failed: Not found" for the disabled spare radio
# and still bring the APs up, so check the hostapd sockets instead.
wifi || true
for i in \$(seq 1 20); do
	[ -S /var/run/hostapd/ap-2g ] && [ -S /var/run/hostapd/ap-5g ] && break
	sleep 1
done
[ -S /var/run/hostapd/ap-2g ] && [ -S /var/run/hostapd/ap-5g ] ||
	{ echo "hostapd did not start the APs, see logread" >&2; exit 1; }

cat > /etc/donghoa.conf <<CONF
name ap$n
iface eth1
key hex:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
hostapd_ctrl_dir /var/run/hostapd
ctrl_socket /var/run/donghoa.sock
CONF
/etc/init.d/donghoa enable
/etc/init.d/donghoa restart
EOF
echo "ap$n provisioned"
