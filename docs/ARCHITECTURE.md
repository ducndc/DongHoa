# DongHoa architecture

## Layering

```
            +-------------------- donghoa (one per AP) -------------------+
 peers <--> | l2  -> msg (TX/RX, ACK, replay) -> peer (remote view)        |
            |                     |                                       |
            |                 steer  <---  policy (pure decisions)        |
            |                     |                                       |
            |   local (BSS/STA tables, events, 11k neighbor DB sync)      |
            |                     |                                       |
            |   hapd (ctrl iface)   survey (nl80211 GET_SURVEY)           |
            |   ------------- os.cpp: every POSIX/Linux call -----------  |
            +---------------------|---------------------|-----------------+
                               hostapd               nl80211
```

DongHoa is written in C++17 without exceptions, RTTI or heap, and links only
libc. It runs as a single-threaded `poll()` loop with a 100 ms tick
(`main.cpp`) and has no dynamic allocation: every table is a `std::array`
inside class `Daemon` (`daemon.hpp`), one static object. The modules below
are `.cpp` files; the coordination modules are `Daemon` member functions.
Only `os.cpp` calls the operating system (see `docs/CODING_CONVENTION.md`).

| Module | Role |
|---|---|
| `proto` | ARCP encoding/decoding, HMAC (wire format: `PROTOCOL.md`). |
| `rrm` | 802.11 helpers: channel/op class, BSSID Info, Neighbor Report, Beacon Request/Report encoding, BTM capability. |
| `policy` | Pure decision functions: triggers, candidate scoring (linear or expected-throughput model), admission, backoff, low-power classification arithmetic. |
| `l2` | Raw `AF_PACKET` ports and UDP "sim" ports for tests. |
| `hapd` | hostapd control interface (commands, events), with the reply parsers in `hapd_parse`. |
| `survey` | nl80211 `GET_SURVEY` over raw generic netlink for channel utilisation and noise: asynchronous (reply read from the main loop), one dump per radio per poll, time spent in the driver measured (`donghoa_cli STATUS`: `survey=nl80211 radios= dumps= last_us= max_us= timeouts= errors=`). |
| `msg` | Periodic broadcasts, reliable unicast (ACK_REQ, retransmit), RX dispatch, learning the path to each peer. |
| `peer` | Peer table, replay window, remote BSS and load, remote STA locations, expiry. |
| `local` | Polls hostapd (`STATUS`, `STA-FIRST/NEXT`, `GET_CONFIG`) and nl80211; keeps the STA table (EWMA of RSSI, throughput); handles hostapd events; installs local sibling and remote BSSes into hostapd's neighbor database (`SET_NEIGHBOR` / `REMOVE_NEIGHBOR`). |
| `steer` | Steering state machine on the source AP, and admission/reservations on the target AP. |
| `devclass` | Low-power (IoT) device classification from each local STA's uplink/downlink traffic variability (arithmetic in `policy`), the device class table shared with peers (STA_CLASS, `PROTOCOL.md` §8), and the restore on (re)association. |
| `amon` | Air monitor: radiotap monitor sockets (BPF-filtered to uplink data and probe requests), STA watches on request, STA_MONITOR_REQ/REPORT. Lets STAs without 11k measurements be steered. |
| `ctrl` | Local control socket used by `donghoa_cli` and the tests. |
| `rrm_log` | Debug dump (log module `rrm`) of the 802.11k/v commands sent to hostapd, their replies and the 11k/v events, raw and decoded with the pure decoders in `rrm.cpp`. Called from `hapd::Conn`, so every caller is covered. |

## Steering state machine (source AP, one transaction per STA)

A rendered flowchart and message sequence are in [STEERING.md](STEERING.md).

```
            trigger (RSSI | band | load round | manual)
                 |
                 v
   +---------> MEASURE ---- beacon reports for all candidates, or timeout ----+
   |             | STA has no 11k beacon support                              |
   |             +---------------------------> evaluate (score, sort) <-------+
   |                                              |
   |              local candidate: admit locally  |  remote candidate
   |                     +------------------------+----------------+
   |                     v                                         v
   |                    BTM <------- STEER_RESP accept ------- NEGOTIATE
   |                     |                                         | reject/timeout:
   |                     |                                         | next candidate
   |    BSS-TM-RESP != 0 | timeout -> fail (backoff)               |
   |                     v                                         v
   |                   ROAM -- STA_EVENT assoc at target -> SUCCESS  (no more
   |                     |-- assoc at another BSS -> WRONG_TARGET    candidates
   |                     '-- timeout -> fail (backoff)               -> abort)
   '-- cooldown / exponential backoff per STA (steer_cooldown_ms .. steer_backoff_max_ms)
```

Triggers, from `onStaPoll` and `runLbRound`:
- **RSSI:** the smoothed RSSI stays below `rssi_low` for `rssi_low_count`
  polls. A candidate must beat the current RSSI by `rssi_hysteresis` and reach
  at least `rssi_min_target`.
- **Band:** a 2.4 GHz STA at or above `band_steer_rssi` is a candidate for a
  5/6 GHz BSS of the same ESS, on this AP or a peer. With `band_steer_6g`
  (default on), a 5 GHz STA at or above `band_steer_6g_rssi` is a candidate
  for a 6 GHz BSS, but only when it advertises 6 GHz operating classes or
  was seen on 6 GHz (an unknown STA is not probed for 6 GHz). The STA must be
  able to use a higher band (below). A band steer in which no candidate gets measured
  backs the STA off exponentially for band steering (`steer_cooldown_ms ×
  2^n`, up to `steer_backoff_max_ms`), until a 5/6 GHz level shows up.

**STA bands.** The Supported Operating Classes element of the (re)association
request (hostapd's `supp_op_classes=`) gives the bands a STA advertises:
classes 81–84 = 2.4 GHz, 115–129 = 5 GHz, 131–137 = 6 GHz, read up to the
130 or 0 delimiter. A band the STA was associated or measured on (11k report
or air monitor) also counts. Automatic steers skip candidate BSSes on bands
the STA neither advertises nor was seen on. A STA without the element counts
as able to use every band, so the measurement decides, as before. A missing
report never proves a band is absent (busy STA, DFS, 6 GHz probing rules).

**Wi-Fi 7 MLO.** hostapd gives each link of an AP MLD its own control socket,
`<netdev>_link<id>`, so each link is one `bss` line (`bss ap-mld0_link0`,
`bss ap-mld0_link1`, …). Its `STATUS` lists the BSS under the netdev name
with `mld_addr[i]` and `mld_link_id[i]`; the survey uses the netdev part of
the name. Links with the same MLD address form one AP MLD, also for peers
(`BSS_INFO` trailer, PROTOCOL.md). An MLD STA is listed on every link under
its MLD address with `peer_addr[<link id>]`:
- It is one STA entry with one RSSI per link. Its RSSI and BSS are those of
  its best link, and it is weak only when every link is (the low-RSSI count
  is the minimum over the links). A link hostapd stops listing is dropped;
  the STA goes when no link is left, or when any link reports it gone.
  Traffic counters come from one link. `donghoa_cli STAS` adds
  `mld links=<bss>:<link id>:<rssi>,…`; `STATUS`/`PEERS` add
  `mld=<addr> link=<id>` to each AP MLD link.
- No band steering: an MLD STA already uses several bands, and link use
  inside the AP MLD is the MLD's job.
- No steer to another link of its own AP MLD, for any reason.
- A steer succeeds when the STA associates on any link of the target AP
  MLD; association back on a link of the source AP MLD is not an outcome.
- A legacy STA associated with one affiliated BSS of an AP MLD is steered
  like any other STA, including to another affiliated BSS.

The fields above come from the hostapd 2025.03 source; they have not been
checked against a running AP MLD (OpenWrt with an MLO-capable driver).

6 GHz allows only WPA3 (SAE), OWE and 802.1X with PMF; hostapd refuses PSK,
FT-PSK and PSK-SHA256 on a 6 GHz BSS. A STA whose association uses one of
those AKMs (hostapd's `AKMSuiteSelector` 00-0f-ac-2/4/6) is taken not to
support WPA3, and 6 GHz is blocked for it even if it advertises 6 GHz. On a
WPA2/WPA3 transition BSS this can miss a WPA3-capable STA that chose PSK;
the STA's RSN capabilities are not visible through hostapd's control
interface. No STA AKM (open BSS, or field missing) blocks nothing.
`donghoa_cli <sock> STAS` shows them per STA as
`bands=<usable>(<class>) adv=<advertised> seen=<seen>`, for example
`bands=2g,5g(dual) adv=2g,5g seen=2g`. `<usable>` is advertised plus seen,
minus blocked bands (then ` no6g=wpa2-psk` is added);
`<class>` is `single`, `dual` or `tri`, or `unknown` when the STA advertised
no operating classes (DongHoa then tries every band).
- **Load:** the BSS utilisation is at or above `util_high`, or `max_sta` is
  reached. Each round moves one STA per overloaded BSS: the weakest idle STA
  (`lb_only_idle`). The target must sit below `util_high - lb_margin`, and the
  STA may lose up to `lb_rssi_tolerance` dB.

The score is `STA-measured target RSSI + band bonus - util_weight * util% / 10`
(`score_model 0`, default). The experimental `score_model 1` scores the
expected throughput instead: `q(RSSI) x peak PHY rate x (1 - util)`, where `q`
is a sigmoid lookup table, and compares it with the STA's current throughput
(see `docs/SDD.md` §6.5).
Candidates with no measurement are ineligible, except for manual steering:
without a STA-side measurement, the source AP can't know the STA would
actually hear the target.

Admission control on the target (`policy_admit`) counts `sta_count +
active reservations` against `max_sta` and checks utilisation against
`util_admit_max`. A reservation lasts `reserve_hold_ms`. It is released by
the STA's association, by STEER_RESULT, by expiry, or by loss of the peer.

## hostapd integration

DongHoa uses only hostapd's control interface. Build hostapd with
`CONFIG_WNM_AP=y` (BSS_TM_REQ) and the RRM/ctrl-iface options of your
distribution. Each BSS needs at least:

```
bss_transition=1          # 802.11v BTM
rrm_neighbor_report=1     # 802.11k neighbor DB / SET_NEIGHBOR
rrm_beacon_report=1       # 802.11k REQ_BEACON
mobility_domain=a1b2      # == donghoa "bss ... mdid=a1b2"
ieee80211r=1
wpa_key_mgmt=FT-PSK WPA-PSK   # or FT-SAE / FT-EAP
ft_over_ds=0
ft_psk_generate_local=1   # FT-PSK; for SAE/EAP configure r0kh/r1kh instead
ctrl_interface=/var/run/hostapd
```

The 802.11r key hierarchy is distributed between APs by hostapd itself (its
RRB on EtherType 0x890D, or locally generated keys for FT-PSK). ARCP does not
carry key material. It only checks MDID consistency (`GET_CONFIG` key_mgmt
must contain an FT AKM when `mdid` is set) and advertises the MDID so that
Neighbor Reports and BTM candidates carry the Mobility Domain bit.

**Commands used:** `ATTACH`, `STATUS`, `GET_CONFIG`, `STA-FIRST`,
`STA-NEXT`, `SET_NEIGHBOR <bssid> ssid=<hex> nr=<hex>`, `REMOVE_NEIGHBOR`,
`REQ_BEACON <sta> <hex>`, `BSS_TM_REQ <sta> pref=1 abridged=1 valid_int=N
neighbor=<bssid>,<info>,<op>,<ch>,<phy>,0301ff`.

**Events used:** `AP-STA-CONNECTED`, `AP-STA-DISCONNECTED`, `BEACON-RESP-RX
<sta> <token> <mode> <hex>`, `BSS-TM-RESP <sta> ... status_code= ...
target_bssid=`.

**Assumptions to verify against your hostapd build.** The parsers tolerate
these fields being absent. They were checked against OpenWrt 25.12.6
(`wpad-mbedtls` 2025.08.26, mac80211_hwsim, see `openwrt/README.md`); other
builds may differ:
- `STA` output fields `signal`, `rx_rate_info` / `tx_rate_info` (100 kbps
  units, e.g. `217 mcs 2 shortGI`), `ext_capab`, and `AKMSuiteSelector`
  printed as `00-0f-ac-4`. Verified.
- `STA` field `supp_op_classes` (hex of the element body, Current Operating
  Class first): present in hostapd 2025.03 `ctrl_iface_ap.c`. Verified on the
  OpenWrt build: wpa_supplicant's hwsim STA shows `adv=2g,5g,6g`.
- 11k/v events dumped by `rrm_log`: `BEACON-REQ-TX-STATUS <sta> <token>
  ack=<0|1>` and `BSS-TM-RESP <sta> status_code=…` (no `dialog_token=` on
  that build). Verified on the OpenWrt build.
- `STATUS` field `chan_util_avg`, used only when the nl80211 survey is not
  available. Verified present.
- The `BEACON-RESP-RX` hex payload starts at the Beacon Report's Operating
  Class field. Verified: a real wpa_supplicant report drove a steer.

hostapd may run as a different user from DongHoa (OpenWrt: `network`). DongHoa
hands its ctrl reply sockets to the owner of hostapd's socket so the replies
can be delivered.

A STA advertises 11k in the RM Enabled Capabilities element of its
(re)association request: octet 0 bits 4/5/6 = Beacon Passive/Active/Table
(OpenWrt shows them as `"rrm"` in `ubus call hostapd.<if> get_clients`;
`0x70` = all three). hostapd refuses `REQ_BEACON` (`FAIL`, nothing sent) for a
mode the STA did not advertise, and its control interface does not expose the
element. So DongHoa tries the configured mode, then active, then passive
(lasting at least 120 TU, one beacon interval), and remembers the first mode
accepted per STA (`bcn=` in `donghoa_cli STAS`). Only when every mode fails is
the STA treated as having no beacon reports (`bcn=none`). Table mode is not a
fallback: it repeats the STA's cached scan results and measures nothing new.
A STA busy with its own scan answers report mode `refused`.

## Known limitations / next steps

- Low-power classification thresholds and α are not calibrated on real IoT
  devices (SDD R16); the class only keeps devices out of automatic steering.

- Channel utilisation comes from the busy time of the radio's in-use channel,
  smoothed with an EWMA. It does not separate the BSS's own airtime from OBSS
  airtime.
- Unassociated-STA RSSI comes only from air monitors (`air_monitor`), which
  hear a STA only on their own channel (uplink data, probe requests). No
  off-channel listening; vendor air-monitor APIs could feed `amon.cpp`.
- `boot_id` replay caveat (see PROTOCOL.md §5).
- The neighbor database holds 20 MHz op classes only. Wide-channel op classes
  are not advertised.
- MLO: no Multi-Link element in neighbor reports or BTM candidates (an MLD
  STA learns the target AP MLD from its beacons when it associates), no
  link reconfiguration or TID-to-link mapping (link use inside an AP MLD is
  left to the MLD), and not yet run against a real AP MLD (see "Wi-Fi 7 MLO").
- STAs mostly discover 6 GHz BSSes through RNR in 2.4/5 GHz beacons or FILS
  discovery, which hostapd configures; DongHoa does not. Neighbor reports
  for 6 GHz use op class 131 (20 MHz) only.
