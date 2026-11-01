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
| `policy` | Pure decision functions: triggers, candidate scoring (linear or expected-throughput model), admission, backoff. |
| `l2` | Raw `AF_PACKET` ports and UDP "sim" ports for tests. |
| `hapd` | hostapd control interface (commands, events), with the reply parsers in `hapd_parse`. |
| `survey` | nl80211 `GET_SURVEY` over raw generic netlink for channel utilisation and noise. |
| `msg` | Periodic broadcasts, reliable unicast (ACK_REQ, retransmit), RX dispatch, learning the path to each peer. |
| `peer` | Peer table, replay window, remote BSS and load, remote STA locations, expiry. |
| `local` | Polls hostapd (`STATUS`, `STA-FIRST/NEXT`, `GET_CONFIG`) and nl80211; keeps the STA table (EWMA of RSSI, throughput); handles hostapd events; installs local sibling and remote BSSes into hostapd's neighbor database (`SET_NEIGHBOR` / `REMOVE_NEIGHBOR`). |
| `steer` | Steering state machine on the source AP, and admission/reservations on the target AP. |
| `amon` | Air monitor: radiotap monitor sockets (BPF-filtered to uplink data and probe requests), STA watches on request, STA_MONITOR_REQ/REPORT. Lets STAs without 11k measurements be steered. |
| `ctrl` | Local control socket used by `donghoa_cli` and the tests. |

## Steering state machine (source AP, one transaction per STA)

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

Triggers, from `steer_on_sta_poll` and `steer_lb_round`:
- **RSSI:** the smoothed RSSI stays below `rssi_low` for `rssi_low_count`
  polls. A candidate must beat the current RSSI by `rssi_hysteresis` and reach
  at least `rssi_min_target`.
- **Band:** a 2.4 GHz STA at or above `band_steer_rssi` is a candidate for a
  5/6 GHz BSS of the same ESS, on this AP or a peer.
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

- Channel utilisation comes from the busy time of the radio's in-use channel,
  smoothed with an EWMA. It does not separate the BSS's own airtime from OBSS
  airtime.
- Unassociated-STA RSSI comes only from air monitors (`air_monitor`), which
  hear a STA only on their own channel (uplink data, probe requests). No
  off-channel listening; vendor air-monitor APIs could feed `amon.cpp`.
- `boot_id` replay caveat (see PROTOCOL.md §5).
- The neighbor database holds 20 MHz op classes only. Wide-channel op classes
  are not advertised.
- No MLO / multi-link awareness.
