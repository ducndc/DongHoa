# ARCP — AP Roaming Coordination Protocol (version 1)

ARCP is a custom Layer-2 protocol that APs in one ESS use to exchange BSS, STA
and RF state and to coordinate STA steering. It deliberately does **not** use
IEEE 1905.1. `src/proto.hpp` is the source of truth for numeric values; this
document describes semantics.

## 1. Transport

| Item | Value |
|---|---|
| Encapsulation | Ethernet II, no IP |
| EtherType | `0x88B5` (IEEE Std 802 Local Experimental EtherType 1) |
| Group address | `03:41:52:43:50:00` (locally administered, multicast) |
| Unicast | Ethernet source address learned from the peer's frames |
| Max ARCP payload | 1400 bytes (header + TLVs), no fragmentation |

**EtherType:** `0x88B5` is reserved for experiments and private protocols. For
a product, get an assigned EtherType and change `ARCP_ETHERTYPE`.

**Medium independence:** ARCP runs on any netdev that carries Ethernet frames.
Bind it to the LAN bridge and it reaches every AP, however the backhaul is
built:
- Wired: Ethernet, or a bridge with Ethernet ports.
- Wi-Fi: a 4-address/WDS link or an 802.11s mesh bridged into the LAN. Either
  carries frames from any source MAC address.
- A 3-address client (STA) uplink only carries frames whose source is its own
  MAC address. To use one, bind ARCP directly to that interface. It then
  reaches only the uplink AP.

A node with several ports sends every message on all of them. Receivers drop
the extra copies using the replay window (§4). For each new message, the port
that delivers the first copy becomes the unicast path to that peer. Unicast
therefore moves to whichever backhaul is working, wired or wireless.

## 2. Header (24 bytes, network byte order)

```
 0      2   3    4     5      6          10         14            20        22
+------+---+----+-----+------+----------+----------+-------------+---------+------+
|magic |ver|type|flags| rsvd |  msg_id  | boot_id  | origin (6)  |body_len | rsvd |
|0x4152| 1 |    |     |  0   |   u32    |   u32    |  AP id      |  u16    |  0   |
+------+---+----+-----+------+----------+----------+-------------+---------+------+
```

- `origin`: the AP identifier. It stays the same whichever port a message
  leaves on.
- `msg_id`: increases by one for each message an AP sends. A retransmission
  reuses the same `msg_id`.
- `boot_id`: a random, non-zero value chosen at startup. When it changes, the
  peer has restarted.
- `flags`: `0x01` ACK_REQ (the receiver must answer with ACK), `0x02` AUTH
  (the last TLV is AUTH).

## 3. TLVs

Each TLV has the format `type (u8) | length (u16) | value`. Receivers ignore
unknown TLV types. They also ignore extra bytes at the end of a known TLV, so
later versions can add fields there.

| Type | Name | Value layout |
|---|---|---|
| 0x01 | AP_INFO | flags u16 (bit0 AIR_MONITOR: answers STA_MONITOR_REQ), hello_ms u16, num_bss u8, name_len u8, name |
| 0x02 | BSS_INFO | bssid 6, freq u16, op_class u8, channel u8, band u8 (2/5/6), bw u8 (0=20..4=320), phy_type u8, caps u16, mdid u16, bssid_info u32, ssid_len u8, ssid, then only for a link of an AP MLD (Wi-Fi 7 MLO): mld_addr 6, link_id u8 (0–14). A receiver that finds no trailer treats the BSS as not affiliated with an AP MLD; an older receiver ignores the trailer. Links of one AP MLD carry the same mld_addr |
| 0x03 | BSS_LOAD | bssid 6, sta_count u16, max_sta u16, util u8 (0–254, 255 = unknown), noise i8, tx_power i8, flags u8 (bit0 accepting steer-in) |
| 0x04 | STA_ENTRY | sta 6, bssid 6, rssi i8, flags u8, connected_s u32, inactive_ms u32, tx_rate_mbps u16, rx_rate_mbps u16, tput_kbps u32 |
| 0x05 | RF_INFO | radio_id u8, freq u16, op_class u8, channel u8, bw u8, util u8, noise i8, tx_power i8 |
| 0x06 | STA_EVENT | sta 6, bssid 6, event u8 (1 assoc, 2 disassoc), reason u16 |
| 0x10 | STEER_REQ | txn u32, sta 6, src_bssid 6, tgt_bssid 6, reason u8, rcpi u8, sta_flags u8, cur_rssi i8 |
| 0x11 | STEER_RESP | txn u32, status u8, hold_ms u16 |
| 0x12 | STEER_RESULT | txn u32, sta 6, outcome u8, btm_status u8 |
| 0x13 | ACK | msg_id u32 |
| 0x14 | STA_MONITOR_REQ | txn u32, sta 6, duration_ms u16, op_class u8, channel u8 (the STA's current channel, a hint) |
| 0x15 | STA_MONITOR_RESULT | txn u32, sta 6, bssid 6, rssi i8 (dBm), samples u16, age_ms u16 (since the last sample) |
| 0xFF | AUTH | 16 bytes: HMAC-SHA256 truncated |

`caps` bits: FT 0x01, BTM 0x02, RRM-NR 0x04, RRM-Beacon 0x08, HT 0x10, VHT
0x20, HE 0x40, EHT 0x80, FT-over-DS 0x100.

`bssid_info` is the 802.11 Neighbor Report BSSID Information field. The
receiving AP sets the Mobility Domain bit itself, and only when its own MDID
matches the advertised one.

STA `flags`: 11k 0x01, 11v 0x02, 11r 0x04, idle 0x08, being steered 0x10.

`rcpi`: the target's RCPI as the STA measured it, taken from an 11k Beacon
Report (dBm = RCPI/2 − 110). 255 means it is not available.

## 4. Messages

| Type | Name | Delivery | TLVs | Period / trigger |
|---|---|---|---|---|
| 0x01 | HELLO | multicast | AP_INFO, BSS_INFO* | `hello_interval_ms`; also sent right away after a new peer is seen |
| 0x02 | BSS_STATUS | multicast | (BSS_INFO, BSS_LOAD)* | `bss_status_interval_ms` |
| 0x03 | STA_STATUS | multicast | STA_ENTRY* (split over several messages if needed) | `sta_status_interval_ms` |
| 0x04 | RF_STATUS | multicast | RF_INFO* (one per operating channel) | `rf_status_interval_ms` |
| 0x05 | STA_EVENT | multicast | STA_EVENT | when a STA associates or disassociates |
| 0x10 | STEER_REQ | unicast, ACK_REQ | STEER_REQ | source AP asks the target AP to accept a STA |
| 0x11 | STEER_RESP | unicast, ACK_REQ | STEER_RESP | target AP's admission decision |
| 0x12 | STEER_RESULT | unicast, ACK_REQ | STEER_RESULT | source AP reports the outcome so the target frees its reservation |
| 0x13 | STA_MONITOR_REQ | unicast, ACK_REQ | STA_MONITOR_REQ | source AP asks a peer with AIR_MONITOR to measure a STA (§7) |
| 0x14 | STA_MONITOR_REPORT | unicast, ACK_REQ | STA_MONITOR_RESULT* | after the watch: one result per BSS of the peer on whose frequency the STA was heard; not sent if it was not heard |
| 0x20 | ACK | unicast | ACK | answers any message that has ACK_REQ set |
| 0x21 | BYE | multicast | — | graceful shutdown |

**Reliability:** a message with ACK_REQ is retransmitted every 300 ms, with
the same `msg_id`, up to 4 times. The receiver ACKs every copy, duplicates
included, but processes a message only once.

**Liveness:** a peer is removed if nothing arrives from it within
`peer_timeout_ms`, or when it sends BYE. A remote BSS is dropped once it has
gone unadvertised for 3×`bss_status_interval_ms` + `hello_interval_ms`. When a
peer or BSS is removed, its entries leave the local hostapd neighbor database.

**Replay window:** for each peer, the receiver keeps a 64-entry sliding window
over `msg_id`, as IPsec does. A message is accepted if its `msg_id` is higher
than the highest seen so far, or falls inside the window without having been
seen. A new `boot_id` resets the window.

## 5. Authentication

With `key` configured, the sender sets the AUTH flag and appends the AUTH TLV
last. The MAC is `HMAC-SHA256(key, header ‖ TLVs before AUTH)` truncated to 16
bytes, with `body_len` already counting the AUTH TLV. A receiver with a key
drops every message without a valid AUTH TLV. A receiver without a key drops
every message that has the AUTH flag, so a key misconfiguration shows up
instead of failing silently.

A passphrase key is turned into a key as `SHA256("arcp-key:" ‖ passphrase)`.

**Known limitation:** the reset on a new `boot_id` lets an attacker replay
messages from a peer's earlier boot. A real deployment should add a persisted,
increasing boot counter or a timestamp check.

## 6. Steering transaction

Status codes in STEER_RESP: 0 accept, 1 unknown BSS, 2 capacity, 3 load,
4 busy, 5 policy.

Outcome codes in STEER_RESULT: 0 success, 1 BTM rejected, 2 BTM timeout,
3 roam timeout, 4 STA joined a different BSS, 5 aborted.

```
 STA          Source AP (donghoa+hostapd)          Target AP (donghoa+hostapd)
  |                     |                                      |
  |  [trigger: RSSI / load / band / manual]                    |
  |<-- 11k Beacon Req --|  (REQ_BEACON, one request for all candidate channels)
  |--- Beacon Report -->|  (BEACON-RESP-RX: RCPI per BSSID)    |
  |                     |  score candidates                    |
  |                     |------ STEER_REQ (ACK_REQ) ---------->|
  |                     |<----- ACK ---------------------------|  admission check,
  |                     |<----- STEER_RESP accept, hold_ms ----|  reserve a slot
  |                     |------ ACK -------------------------->|
  |<-- 11v BTM Req -----|  (BSS_TM_REQ pref=1 abridged=1,      |
  |    candidate=target, preference 255, MD bit if same MDID)  |
  |--- BTM Resp (0) --->|  (BSS-TM-RESP)                       |
  |=== 11r FT (re)association =================================>|
  |                     |<----- STA_EVENT assoc (multicast) ---|  reservation used
  |                     |------ STEER_RESULT success --------->|
```

The negotiation step is skipped when the candidate is another BSS of the same
AP, as in band steering between radios. In that case the source AP runs the
admission check locally.

## 7. Air monitor (STAs without 802.11k measurements)

A STA that does not support 802.11k, or does not answer a Beacon Request
while it is busy, cannot tell the source AP how well it hears the other
BSSes. An AP with a radiotap monitor interface can measure the reverse
direction instead: the RSSI of the STA's own frames.

```
 STA          Source AP                         Peer AP (AIR_MONITOR)
  |  trigger -> MEASURE                                 |
  |<- Beacon Request (if 11k; may be refused/ignored)   |
  |             |---- STA_MONITOR_REQ (ACK_REQ) ------> |  watch the STA for duration_ms
  |~~ uplink data / probe requests ~~~~~~~~~~~~~~~~~~~~>|  (heard on the monitor's channel)
  |             |<--- STA_MONITOR_REPORT: bssid, rssi - |
  |             |  evaluate: 11k level if any, else the monitor's
```

- The source asks only peers that set AIR_MONITOR in AP_INFO and own a
  candidate BSS, so without monitors nothing changes.
- A peer credits samples to its BSSes on the frequency the frame was heard
  on (radiotap channel). A stock radio hears only its own channel: uplink
  data of STAs on that channel, and probe requests of scanning STAs.
- The result is uplink RSSI (STA → AP). The source compares it with its own
  uplink RSSI of the STA, so both sides are measured the same way. A
  configurable offset (`amon_rssi_offset`) can correct for TX-power
  asymmetry.
- A STA's own 11k report of a BSS always wins over a monitor result.

