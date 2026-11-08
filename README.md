# DongHoa — multi-AP roaming, steering and load balancing over Layer 2

DongHoa (daemon `donghoa`) runs on every AP of an ESS, next to hostapd. The APs talk to each
other with **ARCP**, a custom Layer-2 protocol on EtherType 0x88B5 that does
not use IEEE 1905. Over ARCP they exchange BSS state, load, STA state and RF
information, and they coordinate:

- **Assisted roaming:** a STA with a weak signal is measured with an 802.11k
  Beacon Request and moved with an 802.11v BTM Request. The move completes as
  an 802.11r fast transition.
- **Band steering:** a strong 2.4 GHz STA moves to a 5/6 GHz BSS on the same
  AP or on another AP.
- **Load balancing:** an overloaded BSS offloads idle STAs to a lightly loaded
  neighbor. The target AP admits each STA explicitly and reserves capacity for
  it.
- **802.11k neighbor reports:** the hostapd neighbor database fills itself
  from the BSSes that peers advertise.
- **AP-side measurement:** a STA without 802.11k, or too busy to answer a
  Beacon Request, is measured instead by the other APs, from the frames it
  sends: the source multicasts a request, every AP measures with its
  radiotap monitor (`air_monitor`) or the driver's per-STA RSSI API
  (`sta_rssi_api`, vendor placeholder in `src/vendor_rssi.cpp`) and always
  answers, "cannot measure" included, and the source picks the target.
- **Low-power device classification:** each AP recognises IoT devices
  (sensors, cameras, smart plugs) from their traffic: bursty uplink, little
  downlink. The class is shared between APs, so it follows the device and
  survives an AP restart, and keeps such devices out of automatic steering
  (`lp_*` keys; `donghoa_cli DEVCLASS`). Large uploads (`lp_max_mean_bps`)
  and VHT/EHT-capable STAs (`lp_exclude_*`) are not classified low-power.
- **Per-STA roaming threshold:** each STA's RSSI threshold is learned from
  the outcomes of its steers (a STA that keeps refusing is asked later, one
  that gains a lot is moved earlier) and from its own roams, within
  −82…−65 dBm, and follows the STA to other APs (`roam_thr_*`).
- **Learning when to roam (optional):** a small Q-table learns from outcomes
  when to wait and when to steer; off by default, shadow (learn only) or
  active via `rl_roam` or `donghoa_cli RL mode` (`docs/features/15-rl-roaming.md`).
- **Learning which target (optional):** a contextual bandit learns from
  outcomes which kind of eligible candidate works (refused, bounced back,
  or a good roam) and orders candidates by it; off by default, enable with
  `bandit_target` or `donghoa_cli BANDIT mode` (`docs/features/16-target-bandit.md`).
- **Calibrated AP-side levels:** the uplink → downlink offset is learned per
  BSS from STAs measured both ways (`donghoa_cli CALIB`).
- **Real-time metrics:** per-STA signal, inactivity and counters come from
  asynchronous nl80211 station dumps, channel utilisation from the nl80211
  survey; steering ignores stale signal from idle STAs and ends a
  measurement as soon as the STA's reports stop.

ARCP runs over any interface that carries Ethernet frames, such as wired LAN,
bridges, 4-address/WDS or 802.11s Wi-Fi backhaul. Messages are authenticated
with HMAC-SHA256. This first version targets STAs that support 802.11k, v and
r.

## Build and test

```sh
make            # donghoa + donghoa_cli (C++17, no exceptions/RTTI/heap; needs only libc at run time)
make test       # unit tests
make check-deps # verify the binaries need no libstdc++.so
make itest      # end-to-end: 3 daemons + mock hostapd over the UDP sim transport (no root)
```

To cross-compile, set `CXX`, for example
`make CXX=aarch64-openwrt-linux-musl-g++`. For OpenWrt, `openwrt/` has the
package, an SDK build script and QEMU test APs; see `openwrt/README.md`.

## Run

```sh
cp donghoa.conf.example /etc/donghoa.conf  # edit iface, key, bss lines
donghoa -g                                 # optional: per-AP signing key (sign_seed / peer_key lines)
# or 'enroll 1' in the config: keys created automatically, admit a new AP with
donghoa_cli /var/run/donghoa.sock ENROLL approve <ap_id>   # after checking its fingerprint
donghoa -c /etc/donghoa.conf               # needs CAP_NET_RAW; -d all debug, -s syslog
donghoa_cli /var/run/donghoa.sock PEERS    # STATUS | PEERS | STAS | STEERS | DEVCLASS | PING
donghoa_cli /var/run/donghoa.sock LOG debug steer msg   # debug two modules, no restart
donghoa_cli /var/run/donghoa.sock STEER aa:bb:cc:dd:ee:ff [target-bssid]
```

**Debugging.** Log lines name their module, for example `steer:` or `msg:`.
`LOG` shows each module's level; `LOG debug <module>...` raises it at run time
and `LOG info` resets all. With `msg` at debug, every ARCP frame is traced:
`tx STEER_REQ #19 02:00:00:00:00:02 via eth1 [ack-req] [auth]: STEER_REQ AUTH`.
With `rrm` at debug (`LOG debug rrm`, or `log_debug rrm` in the config), the
802.11k/v traffic with hostapd is dumped, raw and decoded: `REQ_BEACON`,
`BSS_TM_REQ`, `SET_NEIGHBOR`, `REMOVE_NEIGHBOR` with their replies, and the
`BEACON-RESP-RX`, `BEACON-REQ-TX-STATUS`, `BSS-TM-RESP`, `BSS-TM-QUERY` events:

```
rrm: wl0 TX BSS_TM_REQ aa:bb:cc:dd:ee:01 pref=1 abridged=1 valid_int=100 neighbor=02:00:00:00:02:00,0x00001eaf,124,149,9,0301ff -> OK
rrm: wl0   11v BTM request -> aa:bb:cc:dd:ee:01: candidate 02:00:00:00:02:00 op_class 124 ch 149 phy 9 info [reach=3 sec key_scope qos rrm imm_ba md ht vht] cand_pref 255; pref_list=1 abridged=1 valid_int=100
rrm: wl0 RX BSS-TM-RESP aa:bb:cc:dd:ee:01 dialog_token=1 status_code=0 bss_termination_delay=0 target_bssid=02:00:00:00:02:00
rrm: wl0   11v BTM response <- aa:bb:cc:dd:ee:01: status 0 (accept) target 02:00:00:00:02:00
```

Modules: main l2 msg peer hapd local steer policy amon survey ctrl config rrm class.

hostapd needs `bss_transition=1`, `rrm_neighbor_report=1`,
`rrm_beacon_report=1` and an FT configuration whose `mobility_domain` matches
the `mdid=` of each `bss` line. See `docs/ARCHITECTURE.md`.

## Documentation

- `docs/features/`: **feature guide**, one document per feature (transport,
  peer discovery, neighbor reports, local monitoring, steering engine, RSSI
  roaming, band steering, load balancing, AP-side measurement, low-power
  classification, MLO, control and logging, configuration and OpenWrt,
  verification), each with data flow, algorithm, diagrams and explanation.
  Start at `docs/features/README.md`.
- `docs/PROTOCOL.md`: ARCP wire format, messages, reliability, security,
  steering sequence.
- `docs/CODING_CONVENTION.md`: coding convention based on MISRA C++:2023,
  with deviations (all system-interface code confined to `src/os.cpp`) and
  the current baseline.
- `docs/SRS.md`: software requirements (numbered, with verification
  matrix).
- `docs/SDD.md`: software design (runtime, data, components, error handling,
  design decisions, risks, traceability to the SRS).
- `docs/ARCHITECTURE.md`: modules, state machine, policy, hostapd
  integration, assumptions and limitations.
