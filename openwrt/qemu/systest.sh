#!/bin/sh
# SPDX-License-Identifier: MIT
#
# System test on the QEMU OpenWrt testbed: real hostapd and wpa_supplicant on
# mac80211_hwsim, ARCP over the backhaul between the VMs.
#
#   systest.sh              run every scenario
#   systest.sh S4 S9        run selected scenarios (S3 always runs: it sets up the
#                           STA; S5 also runs S4, which puts the STA on 2.4 GHz)
#
# Needs ap1 and ap2 started and provisioned (vm.sh, provision.sh). ap1's spare
# radio becomes the test STA. While running, the steering cooldown is 3 s and
# steer/amon debug logging is on (logread keeps the candidate scores of a
# failed steer); /etc/donghoa.conf and /etc/config/wireless are restored at
# the end.

VM="$(dirname "$0")/vm.sh"
PASS=0
FAIL=0
SUMMARY=""

# Shell helpers available to every remote snippet.
R='C=/var/run/donghoa.sock
mark() { logger -t SYSTEST "=== $1"; }
since() { logread | sed -n "/SYSTEST: === $1\$/,\$p"; }
waitlog() { i=0; until since "$1" | grep -qE "$2"; do i=$((i+1)); [ $i -ge $3 ] && return 1; sleep 1; done; }
cool() { i=0; until donghoa_cli $C STAS 2>/dev/null | grep -q "backoff=-"; do i=$((i+1)); [ $i -ge 60 ] && return 1; sleep 1; done; }
link() { iw dev sta0 link 2>/dev/null | awk "/Connected/{print \$3}"; }
waitlink() { i=0; until [ -n "$(link)" ]; do i=$((i+1)); [ $i -ge 60 ] && return 1; sleep 1; done; }
# "wifi" reloads in the background: wait for the old BSS to go first.
down() { i=0; until donghoa_cli $C STATUS 2>/dev/null | grep -qE "^$1 down"; do i=$((i+1)); [ $i -ge 15 ] && return 1; sleep 1; done; }
up() { i=0; until donghoa_cli $C STATUS 2>/dev/null | grep -qE "^$1 up"; do i=$((i+1)); [ $i -ge 40 ] && return 1; sleep 1; done; }
restart() { /etc/init.d/donghoa restart; i=0; until donghoa_cli $C PING >/dev/null 2>&1; do i=$((i+1)); [ $i -ge 40 ] && return 1; sleep 1; done; }
nrcount() { ubus call hostapd.$1 rrm_nr_list 2>/dev/null | grep -c ARCP-TEST; }
'

rv() { # <ap> <snippet>: run with the helpers
	n=$1
	shift
	"$VM" ssh "$n" "$R
$*"
}

result() { # <name> <0 = pass> <detail>
	if [ "$2" -eq 0 ]; then
		PASS=$((PASS + 1))
		s=PASS
	else
		FAIL=$((FAIL + 1))
		s=FAIL
	fi
	line=$(printf '%-4s  %-52s %s' "$s" "$1" "$3")
	echo "$line"
	SUMMARY="$SUMMARY$line
"
}

want() { # scenario selected?
	[ -z "$SELECT" ] && return 0
	case " $SELECT " in *" $1 "*) return 0 ;; esac
	return 1
}

B1_2G=02:a1:00:00:01:00
B1_5G=02:a1:00:00:01:01
B2_5G=02:a1:00:00:02:01

# Low-power classification is off while testing, except in S15: the test
# STA only ever sends small uplink frames, which is a sensor's traffic
# shape, and a class learned over hours of uptime would keep it out of
# automatic steering (S5, S7). Both daemons are stopped before either
# starts, so no class record survives in a peer's table.
SYSTEST_CONF='printf "steer_cooldown_ms 3000\nlog_debug steer,amon\nlp_classify 0\n" >> /etc/donghoa.conf'

setup() {
	for n in 1 2; do
		rv $n 'cp /etc/donghoa.conf /tmp/donghoa.conf.systest
cp /etc/config/wireless /tmp/wireless.systest
'"$SYSTEST_CONF"'
/etc/init.d/donghoa stop' || return 1
	done
	for n in 1 2; do
		rv $n 'restart' || return 1
	done
}

cleanup() {
	echo "--- restoring configuration"
	for n in 1 2; do
		rv $n 'iw dev mon1 del 2>/dev/null
if [ "$(md5sum < /etc/config/wireless)" != "$(md5sum < /tmp/wireless.systest)" ]; then cp /tmp/wireless.systest /etc/config/wireless; wifi 2>/dev/null; fi
[ -f /tmp/donghoa.conf.systest ] && cp /tmp/donghoa.conf.systest /etc/donghoa.conf
restart' >/dev/null 2>&1
	done
}

# ---- scenarios ----

s1() {
	a=$(rv 1 'donghoa_cli $C PEERS | grep -c "^peer"')
	b=$(rv 2 'donghoa_cli $C PEERS | grep -c "^peer"')
	[ "$a" = 1 ] && [ "$b" = 1 ]
	result "S1  peer discovery, HMAC-authenticated L2" $? "ap1 sees $a peer, ap2 sees $b"
}

s2() {
	out=$(rv 1 'echo "$(nrcount ap-2g) $(nrcount ap-5g)"')
	[ "$out" = "3 3" ]
	result "S2  802.11k neighbor DB filled from peers" $? "entries ap-2g/ap-5g: $out (expect 3 3)"
}

s3() {
	out=$(rv 1 'if [ ! -d /sys/class/net/sta0 ]; then
	s=wireless.default_radio2
	uci set wireless.radio2.disabled=0; uci set wireless.radio2.band=5g; uci set wireless.radio2.channel=36
	uci set $s.disabled=0; uci set $s.mode=sta; uci -q delete $s.network; uci set $s.ifname=sta0
	uci set $s.ssid=ARCP-TEST; uci set $s.encryption=psk2+ccmp; uci set $s.key=testpassphrase
	uci set $s.ieee80211r=1; uci set $s.mobility_domain=a1b2; uci commit wireless; wifi
fi
waitlink; i=0
until donghoa_cli $C STAS | grep -q "^sta "; do i=$((i+1)); [ $i -ge 20 ] && break; sleep 1; done
cat /sys/class/net/sta0/address; donghoa_cli $C STAS | grep "^sta "')
	STA=$(echo "$out" | head -1)
	echo "$out" | grep -q "flags=kvr"
	result "S3  STA associated, tracked with 11k/v/r flags" $? "$(echo "$out" | tail -1 | cut -c1-72)"
}

s4() {
	out=$(rv 1 'cool; i=0
while [ "$(link)" != '"$B1_5G"' ] && [ $i -lt 20 ]; do i=$((i+1)); sleep 1; done
m=S4-$$; mark $m
donghoa_cli $C STEER '"$STA $B1_2G"' >/dev/null
waitlog $m "finished|no suitable" 20
since $m | grep -E "finished" | head -1
echo "reports=$(since $m | grep -c "BEACON-RESP-RX .* 00 ") refused=$(since $m | grep -c "BEACON-RESP-RX .* 04")"
since $m | grep -o "auth_alg=ft" | head -1')
	echo "$out" | grep -q "finished: success" && echo "$out" | grep -q "reports=[2-9] refused=0" &&
		echo "$out" | grep -q "auth_alg=ft"
	result "S4  manual steer 5->2.4 GHz: 11k (1 req) + BTM + FT" $? \
		"$(echo "$out" | grep -o 'success after [0-9]* ms'); $(echo "$out" | grep -o 'reports=.*')"
}

s5() {
	out=$(rv 1 'm=S5-$$; mark $m
waitlog $m "reason band" 20 && waitlog $m "\(band\) finished|band\): no suitable" 15
since $m | grep -E "\(band\)" | tail -1; echo "link=$(link)"
since $m | grep -E "cand |unsupported|no suitable" | sed "s/.*\] /  /"
donghoa_cli $C STAS | grep "^sta " | sed "s/^/  state: /"; donghoa_cli $C STEERS | sed "s/^/  steers: /"')
	echo "$out" | grep -q "(band) finished: success" && echo "$out" | grep -q "link=$B1_5G"
	r=$?
	result "S5  automatic band steering 2.4->5 GHz" $r "$(echo "$out" | grep -o 'success after [0-9]* ms')"
	[ $r -eq 0 ] || echo "$out" | grep "^  "
}

s6() {
	rv 2 'mark S6-ap2' >/dev/null
	out=$(rv 1 'cool; m=S6-$$; mark $m
donghoa_cli $C STEER '"$STA $B2_5G"' >/dev/null
waitlog $m "finished|no suitable" 20
since $m | grep -E "asking AP|BTM rejected|finished" | sed "s/.*\[INF\] //"')
	sleep 2
	out2=$(rv 2 'since S6-ap2 | grep -E "steer-in request|btm-reject" | sed "s/.*\[INF\] //"
echo "resv=$(donghoa_cli $C STEERS | grep -c reservation)"')
	echo "$out" | grep -q "asking AP" && echo "$out" | grep -q "BTM rejected, status 7" &&
		echo "$out2" | grep -q "accept" && echo "$out2" | grep -q "btm-reject" &&
		echo "$out2" | grep -q "resv=0"
	result "S6  cross-AP: STEER_REQ/RESP, BTM reject, RESULT" $? \
		"ap2 accepted, STA refused (status 7), reservation released"
}

s7() {
	out=$(rv 1 'echo "score_model 1" >> /etc/donghoa.conf; restart; waitlink; sleep 4
m=S7-$$; mark $m
donghoa_cli $C STEER '"$STA $B1_2G"' >/dev/null
waitlog $m "\(manual\) finished" 20
waitlog $m "\(band\): no suitable|\(band\) finished" 25
since $m | grep -E "\(band\)" | tail -1; echo "link=$(link)"')
	echo "$out" | grep -q "(band): no suitable candidate" && echo "$out" | grep -q "link=$B1_2G"
	result "S7  tput model: no band steer when 5 GHz no faster" $? "both HT20: STA kept on 2.4 GHz"
}

s8() {
	out=$(rv 1 'uci set wireless.radio1.htmode=VHT80; uci commit wireless; wifi 2>/dev/null
down ap-5g; up ap-5g; waitlink
if [ "$(link)" != '"$B1_2G"' ]; then cool; donghoa_cli $C STEER '"$STA $B1_2G"' >/dev/null; sleep 3; fi
m=S8-$$; mark $m
waitlog $m "\(band\) finished" 45
since $m | grep -E "BTM request|\(band\)" | tail -2 | sed "s/.*\[INF\] //"; echo "link=$(link)"
uci set wireless.radio1.htmode=HT20; uci commit wireless; wifi 2>/dev/null
sed -i "/^score_model/d" /etc/donghoa.conf; restart; up ap-5g; waitlink')
	echo "$out" | grep -q "(band) finished: success" && echo "$out" | grep -q "link=$B1_5G"
	result "S8  tput model: band steer to faster VHT80 BSS" $? "$(echo "$out" | grep -o 'score [0-9]*' | head -1) kbps expected"
}

s9() {
	out=$(rv 1 'phy=phy$(iw dev ap-5g info | awk "/wiphy/{print \$2}")
i=0; while [ "$(link)" != '"$B1_5G"' ] && [ $i -lt 30 ]; do i=$((i+1)); sleep 1; done
iw phy $phy interface add mon1 type monitor && ip link set mon1 up
echo "air_monitor mon1" >> /etc/donghoa.conf; restart
m=S9-$$; mark $m
donghoa_cli $C MONITOR '"$STA"' 3000 >/dev/null; sleep 1; iw dev sta0 scan trigger >/dev/null 2>&1
waitlog $m "heard by|not heard" 10
since $m | grep -o "heard by.*" | head -1
echo "kernel=$(iw dev ap-5g station dump | awk "/signal:/{print \$2; exit}")"
sed -i "/^air_monitor /d" /etc/donghoa.conf; iw dev mon1 del; restart')
	amon=$(echo "$out" | sed -n 's/.*: \(-[0-9]*\) dBm.*/\1/p')
	kern=$(echo "$out" | sed -n 's/kernel=//p')
	[ -n "$amon" ] && [ -n "$kern" ] && [ $((amon - kern)) -le 3 ] && [ $((kern - amon)) -le 3 ]
	result "S9  air monitor: radiotap RSSI of the STA" $? "monitor ${amon:-?} dBm, station table ${kern:-?} dBm"
}

s10() {
	out=$(rv 1 'm=S10-$$; mark $m; wifi 2>/dev/null
waitlog $m "bss ap-2g up" 40; waitlog $m "bss ap-5g up" 40
echo "down=$(since $m | grep -c "bss ap-.g down") up=$(since $m | grep -c "bss ap-.g up:")"
echo "pid=$(pgrep -f /usr/sbin/donghoa | head -1) stat=$(donghoa_cli $C STATUS | grep -c " up$")"; waitlink')
	echo "$out" | grep -q "up=2" && echo "$out" | grep -q "stat=2"
	result "S10 hostapd restart: reconnect without restart" $? "$(echo "$out" | head -1)"
}

s11() {
	out=$(rv 1 'm=S11-$$; mark $m
uci delete wireless.default_radio1.ifname; uci commit wireless; reload_config
up phy1-ap0; a=$(grep "^bss" /var/run/donghoa.conf | tr "\n" ";")
uci set wireless.default_radio1.ifname=ap-5g; uci commit wireless; reload_config
up ap-5g; b=$(grep "^bss" /var/run/donghoa.conf | tr "\n" ";")
echo "renamed=$a"; echo "restored=$b"; waitlink')
	echo "$out" | grep -q "renamed=.*bss phy1-ap0 mdid=a1b2 max_sta=64" &&
		echo "$out" | grep -q "restored=.*bss ap-5g mdid=a1b2 max_sta=64"
	result "S11 bss lines from UCI follow an interface rename" $? "ap-5g -> phy1-ap0 -> ap-5g"
}

s12() {
	out=$(rv 1 'printf "iface eth1\nbss ap-2g\nsim_port abc\n" > /tmp/bad.conf
/usr/sbin/donghoa -c /tmp/bad.conf 2>&1 | head -1; echo "rc=$?"
/usr/sbin/donghoa -c /tmp/bad.conf >/dev/null 2>&1; echo "exit=$?"; rm -f /tmp/bad.conf')
	echo "$out" | grep -q "bad.conf:3: invalid line" && echo "$out" | grep -q "exit=1"
	result "S12 strict config: bad value rejected with line" $? "$(echo "$out" | head -1 | sed 's/.*\] //')"
}

s13() {
	m13=S13-$$; rv 1 "mark $m13" >/dev/null
	rv 2 'sed -i "s/^key .*/key hex:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100/" /etc/donghoa.conf; restart' >/dev/null
	sleep 10
	mid=$(rv 1 'echo "lost=$(since '"$m13"' | grep -c "lost") peers=$(donghoa_cli $C PEERS | grep -c "^peer") nr=$(nrcount ap-2g)"')
	rv 2 'cp /tmp/donghoa.conf.systest /etc/donghoa.conf; '"$SYSTEST_CONF"'; restart' >/dev/null
	end=$(rv 1 'i=0; until donghoa_cli $C PEERS | grep -q "^peer"; do i=$((i+1)); [ $i -ge 20 ] && break; sleep 1; done
sleep 3; echo "peers=$(donghoa_cli $C PEERS | grep -c "^peer") nr=$(nrcount ap-2g)"')
	echo "$mid" | grep -q "lost=1 peers=0 nr=1" && echo "$end" | grep -q "peers=1 nr=3"
	result "S13 BYE + wrong key rejected, recovery" $? "wrong key: $mid; restored: $end"
}

s14() {
	# AP-side measurement (PROTOCOL.md §7), towards AP2's 5 GHz BSS, which
	# the STA cannot hear (another VM): only AP2 can measure it.
	# a) AP2 has no monitor and no driver RSSI API: it answers "unsupported"
	#    at once, and AP1 does not wait out the measurement time for it.
	a=$(rv 1 'cool; m=S14a-$$; mark $m
donghoa_cli $C STEER '"$STA $B2_5G"' >/dev/null
waitlog $m "finished|no suitable" 20
since $m | grep -E "measurement requested|AP [0-9a-f:]* (unsupported|measured|not heard)" |
	awk "{for (i=1;i<=NF;i++) if (\$i ~ /^[0-9]+\.[0-9]+\$/) {print \$i, \$0; break}}" |
	awk "/requested/{t=\$1} /unsupported/ && t {printf \"answer_ms=%d\\n\", (\$1-t)*1000; exit}"')
	# b) AP2 measures with its (simulated) driver API: AP1 gets the level.
	rv 2 'echo "ap-5g '"$STA"' -61" > /tmp/systest_rssi
echo "sta_rssi_sim /tmp/systest_rssi" >> /etc/donghoa.conf; restart; mark S14b-ap2' >/dev/null
	b=$(rv 1 'i=0; until donghoa_cli $C PEERS | grep -q "^peer"; do i=$((i+1)); [ $i -ge 20 ] && break; sleep 1; done
cool; m=S14b-$$; mark $m
donghoa_cli $C STEER '"$STA $B2_5G"' >/dev/null
waitlog $m "finished|no suitable" 20
since $m | grep -oE "heard by '"$B2_5G"' .*: -?[0-9]+ dBm|AP [0-9a-f:]* measured" | head -2')
	c=$(rv 2 'since S14b-ap2 | grep -c "asks to measure '"$STA"'"
sed -i "/^sta_rssi_sim /d" /etc/donghoa.conf; rm -f /tmp/systest_rssi; restart')
	ms=$(echo "$a" | sed -n 's/answer_ms=//p')
	[ -n "$ms" ] && [ "$ms" -lt 500 ] && echo "$b" | grep -q -- "-61 dBm" && echo "$b" | grep -q "measured" &&
		[ "$(echo "$c" | head -1)" -ge 1 ]
	result "S14 AP-side measurement: multicast req, every AP answers" $? \
		"unsupported answered in ${ms:-?} ms; driver API: $(echo "$b" | grep -o -- '-[0-9]* dBm' | head -1)"
}

s15() {
	# Low-power classification on real hostapd counters. The idle STA must
	# stay normal (an idle poll is no evidence); uplink-only traffic (ARP
	# requests for an address nobody has, no reply) makes it low-power, and
	# the class reaches AP2.
	out=$(rv 1 'printf "lp_classify 1\nlp_threshold 4\nlp_hysteresis 1\nlp_min_samples 3\n" >> /etc/donghoa.conf; restart; waitlink
m=S15-$$; mark $m; sleep 10
echo "idle=$(donghoa_cli $C STAS | grep "^sta '"$STA"'" | grep -o "class=[a-z-]*")"
ip addr add 10.99.0.2/24 dev sta0
ping -I sta0 -c 30 -i 1 10.99.0.1 >/dev/null 2>&1 &
waitlog $m "classified low-power" 30
echo "busy=$(donghoa_cli $C STAS | grep "^sta '"$STA"'" | grep -o "class=[a-z-]*")"
kill %1 2>/dev/null; ip addr del 10.99.0.2/24 dev sta0')
	sleep 2
	peer=$(rv 2 'donghoa_cli $C DEVCLASS | grep "'"$STA"'" | grep -o "class=[a-z-]*"')
	# Forget the class on both APs (each would hand it back to the other).
	rv 2 '/etc/init.d/donghoa stop' >/dev/null
	rv 1 'sed -i "/^lp_classify 1$/d; /^lp_threshold 4$/d; /^lp_hysteresis 1$/d; /^lp_min_samples 3$/d" /etc/donghoa.conf; restart' >/dev/null
	rv 2 'restart' >/dev/null
	echo "$out" | grep -q "idle=class=normal" && echo "$out" | grep -q "busy=class=low-power" &&
		[ "$peer" = "class=low-power" ]
	result "S15 low-power class: idle stays normal, uplink-only -> low" $? \
		"$(echo "$out" | grep -E "idle|busy" | tr "\n" " ")ap2: ${peer:-none}"
}

s16() {
	# Per-STA metrics from nl80211 station dumps, not a blocking hostapd
	# STA-FIRST/STA-NEXT round per STA every poll (resync every 10 s).
	out=$(rv 1 'waitlink; d0=$(donghoa_cli $C STATUS | sed -n "s/^station_dump=nl80211 dumps=\([0-9]*\).*/\1/p")
donghoa_cli $C LOG debug hapd >/dev/null; m=S16-$$; mark $m; sleep 12; donghoa_cli $C LOG info hapd >/dev/null
d1=$(donghoa_cli $C STATUS | sed -n "s/^station_dump=nl80211 dumps=\([0-9]*\).*/\1/p")
echo "dumps=$((d1 - d0)) next=$(since $m | grep -c "> STA-NEXT") src=$(donghoa_cli $C STATUS | grep -c "sta_src=nl80211")"
b=$(link); dev=$(iw dev ap-2g station dump | grep -q Station && echo ap-2g || echo ap-5g)
echo "rssi=$(donghoa_cli $C STAS | grep "^sta '"$STA"'" | sed -n "s/.* rssi=\(-[0-9]*\) .*/\1/p")"
echo "kernel=$(iw dev $dev station dump | awk "/signal avg:/{print \$3; exit}")"')
	dumps=$(echo "$out" | sed -n 's/.*dumps=\([0-9]*\).*/\1/p')
	next=$(echo "$out" | sed -n 's/.*next=\([0-9]*\).*/\1/p')
	src=$(echo "$out" | sed -n 's/.*src=\([0-9]*\).*/\1/p')
	rssi=$(echo "$out" | sed -n 's/^rssi=//p')
	kern=$(echo "$out" | sed -n 's/^kernel=//p')
	[ "${dumps:-0}" -ge 10 ] && [ "${next:-99}" -le 2 ] && [ "${src:-0}" -ge 2 ] && [ -n "$rssi" ] && [ -n "$kern" ] &&
		[ $((rssi - kern)) -le 3 ] && [ $((kern - rssi)) -le 3 ]
	result "S16 STA metrics from nl80211 station dumps" $? \
		"${dumps:-?} dumps / ${next:-?} STA-NEXT in 12 s; rssi ${rssi:-?} vs kernel avg ${kern:-?} dBm"
}

# ---- main ----

SELECT="$*"
trap cleanup EXIT INT TERM
echo "--- preparing (cooldown 3 s while testing)"
setup || { echo "setup failed: are ap1 and ap2 running and provisioned?"; exit 2; }
STA=""
for s in s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16; do
	id=$(echo "$s" | tr s S)
	if [ "$s" = s3 ] || want "$id" || { [ "$s" = s4 ] && want S5; }; then
		$s
	fi
done
echo
printf '%s' "$SUMMARY"
echo "--- $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
