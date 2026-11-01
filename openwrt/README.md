# DongHoa on OpenWrt

- `donghoa/`: OpenWrt package (feed layout): Makefile, procd init script,
  default `/etc/donghoa.conf`.
- `build.sh`: builds the package with the official OpenWrt SDK inside Docker
  (the SDK needs gawk and other host tools).
- `qemu/`: x86-64 OpenWrt test APs under QEMU/KVM, no root needed.

Tested with OpenWrt 25.12.6 (apk) and `wpad-mbedtls` 2025.08.26.

## Build the package

```sh
openwrt/build.sh                      # x86/64, 25.12.6: for the QEMU VMs
openwrt/build.sh mediatek/filogic     # your router's target/subtarget
openwrt/build.sh ramips/mt7621 24.10.8
```

The first run downloads and checks the SDK into `build/openwrt/`. The script
prints the path of the package (`.apk` on 25.x, `.ipk` on 24.x). To find
your router's target, run `ubus call system board` on it and look at
`release.target`.

To use the feed in your own buildroot or SDK instead, add this line to
`feeds.conf`:

    src-link donghoa /path/to/this/repo/openwrt

## Test APs in QEMU

```sh
APK=$(openwrt/build.sh | tail -1)
openwrt/qemu/vm.sh start 1 && openwrt/qemu/vm.sh start 2
openwrt/qemu/provision.sh 1 "$APK" & openwrt/qemu/provision.sh 2 "$APK"; wait
openwrt/qemu/vm.sh ssh 1 donghoa_cli /var/run/donghoa.sock PEERS
```

Each VM is one AP with two hostapd BSSes on mac80211_hwsim: `ap-2g` (ch 1)
and `ap-5g` (ch 36). Both use SSID `ARCP-TEST`, FT-PSK in mobility domain
`a1b2`, 802.11k and 802.11v. eth0 (br-lan) is SSH and internet through the
QEMU NAT; SSH reaches AP n at `127.0.0.1:222n`. eth1 is a shared Ethernet
segment between all VMs, and ARCP runs over it with raw sockets. Stop a VM
with `vm.sh stop <n>`. To reset it, delete `build/openwrt/vm/ap<n>.qcow2`.

hwsim radios in different VMs cannot hear each other. A STA can therefore
roam between the two BSSes of one VM, but not between VMs. A steer towards
another VM's BSS still runs the whole ARCP negotiation; the STA then rejects
the BTM with status 7.

### System test

```sh
openwrt/qemu/systest.sh          # all 13 scenarios, about 5 minutes
openwrt/qemu/systest.sh S4 S9    # selected ones
```

It covers discovery, the neighbor DB, local, band and cross-AP steering with
real 11k/11v/11r frames, both scoring models, the air monitor, hostapd
restarts, bss lines from UCI, strict config parsing, and BYE / wrong-key
handling. It shortens the steering cooldown while it runs and restores
`/etc/donghoa.conf` and `/etc/config/wireless` afterwards.

### Check a STA's 802.11k support

```sh
ubus call hostapd.ap-5g get_clients | grep -A6 '"rrm"'   # RM Enabled Capabilities
donghoa_cli /var/run/donghoa.sock STAS                     # bcn=active|passive|none
```

The first `"rrm"` byte comes from the STA's (re)association request: `0x10`
Beacon Passive, `0x20` Beacon Active, `0x40` Beacon Table (`112` = `0x70` =
all three). hostapd refuses a beacon request in a mode the STA did not
advertise; DongHoa then falls back from active to passive and shows the mode
that worked (`unknown` until the STA's first measurement since the daemon
started).

### Test STA

The spare radio of a VM can act as a client:

```sh
openwrt/qemu/vm.sh ssh 1 '
s=wireless.default_radio2
uci set wireless.radio2.disabled=0
uci set wireless.radio2.band=5g; uci set wireless.radio2.channel=36
uci set $s.disabled=0; uci set $s.mode=sta; uci delete $s.network
uci set $s.ifname=sta0; uci set $s.ssid=ARCP-TEST
uci set $s.encryption=psk2+ccmp; uci set $s.key=testpassphrase
uci set $s.ieee80211r=1; uci set $s.mobility_domain=a1b2
uci commit wireless; wifi'
openwrt/qemu/vm.sh ssh 1 'iw dev sta0 link'
openwrt/qemu/vm.sh ssh 1 donghoa_cli /var/run/donghoa.sock STAS
# after the 30 s join cooldown:
openwrt/qemu/vm.sh ssh 1 donghoa_cli /var/run/donghoa.sock STEER 02:00:00:00:02:00 02:a1:00:00:01:00
openwrt/qemu/vm.sh ssh 1 logread -e donghoa
```

A STA on 2.4 GHz with a strong signal is moved back to 5 GHz by band
steering about 30 s later. That is the default policy (`band_steer_rssi`).

## On a real router

```sh
scp -O donghoa-*.apk root@192.168.1.1:/tmp/   # -O: dropbear has no sftp
ssh root@192.168.1.1 'apk add --allow-untrusted /tmp/donghoa-*.apk'
```

On 24.x, use `opkg install /tmp/donghoa_*.ipk` instead. Then set up the
router:

1. In `/etc/config/wireless`, set the following on every AP wifi-iface of
   the ESS: `ieee80211r '1'`, `mobility_domain '<4 hex>'`,
   `ft_psk_generate_local '1'` (PSK) or the R0KH/R1KH setup, `ieee80211k '1'`
   and `bss_transition '1'`. Then run `wifi`. `wpad-basic-*` may lack some of
   this; `wpad-mbedtls` or `wpad-openssl` has everything.
2. Edit `/etc/donghoa.conf`. Set a unique `name`, the same `key` on all APs
   and `iface br-lan`. Leave out `bss` lines: the init script then manages
   every AP interface of `/etc/config/wireless` that is up. It takes the
   runtime interface name (`phy<N>-ap<M>` unless `option ifname` is set),
   the effective `mobility_domain` as `mdid` and `maxassoc` as `max_sta`, and
   writes the result to `/var/run/donghoa.conf`. A wireless change made
   through uci/LuCI (`reload_config`) regenerates it and restarts the
   service. To choose BSSes yourself, list `bss` lines; they are then used
   unchanged.
3. Run `service donghoa enable && service donghoa restart`, then check with
   `logread -e donghoa` and `donghoa_cli /var/run/donghoa.sock PEERS`.

**Air monitor (optional).** To steer STAs that give no 802.11k reports, give
the APs a monitor interface on each radio and name it in the config:

```sh
iw phy phy1 interface add mon1 type monitor && ip link set mon1 up
echo "air_monitor mon1" >> /etc/donghoa.conf && service donghoa restart
donghoa_cli /var/run/donghoa.sock MONITOR <sta-mac> 3000   # check: result in logread
```

The interface does not survive a reboot or a `wifi` restart; create it from
`/etc/rc.local` or a hotplug script. A radio hears STAs only on its own
channel.

DongHoa logs to syslog (`logread -e donghoa`) with real priorities
(`daemon.err` … `daemon.debug`). To debug one area without a restart:
`donghoa_cli /var/run/donghoa.sock LOG debug steer`, and `LOG info` to go
back. For the next boot, put `log_debug steer` in `/etc/donghoa.conf`.
