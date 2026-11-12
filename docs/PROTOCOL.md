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
| Max ARCP payload | 1450 bytes (header + TLVs), no fragmentation |

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
- `boot_id`: a random, non-zero value chosen at startup. A receiver adopts a
  peer's `boot_id` only after the peer answered a CHALLENGE from that boot
  (§4); a verified new `boot_id` from a known peer means it restarted.
- `flags`: `0x01` ACK_REQ (the receiver must answer with ACK), `0x02` AUTH
  (the last TLV is AUTH), `0x04` SIG (a SIG TLV comes last, or just before
  AUTH).

## 3. TLVs

Each TLV has the format `type (u8) | length (u16) | value`. Receivers ignore
unknown TLV types. They also ignore extra bytes at the end of a known TLV, so
later versions can add fields there.

| Type | Name | Value layout |
|---|---|---|
| 0x01 | AP_INFO | flags u16 (bit0 AIR_MONITOR: has a monitor interface or the driver per-STA RSSI API; informational, every AP answers STA_MONITOR_REQ), hello_ms u16, num_bss u8, name_len u8, name |
| 0x02 | BSS_INFO | bssid 6, freq u16, op_class u8, channel u8, band u8 (2/5/6), bw u8 (0=20..4=320), phy_type u8, caps u16, mdid u16, bssid_info u32, ssid_len u8, ssid, then only for a link of an AP MLD (Wi-Fi 7 MLO): mld_addr 6, link_id u8 (0–14). A receiver that finds no trailer treats the BSS as not affiliated with an AP MLD; an older receiver ignores the trailer. Links of one AP MLD carry the same mld_addr |
| 0x03 | BSS_LOAD | bssid 6, sta_count u16, max_sta u16, util u8 (0–254, 255 = unknown), noise i8, tx_power i8, flags u8 (bit0 accepting steer-in) |
| 0x04 | STA_ENTRY | sta 6, bssid 6, rssi i8, flags u8, connected_s u32, inactive_ms u32, tx_rate_mbps u16, rx_rate_mbps u16, tput_kbps u32 |
| 0x05 | RF_INFO | radio_id u8, freq u16, op_class u8, channel u8, bw u8, util u8, noise i8, tx_power i8 |
| 0x06 | STA_EVENT | sta 6, bssid 6, event u8 (1 assoc, 2 disassoc), reason u16 |
| 0x07 | STA_CLASS | sta 6, class u8 (0 normal, 1 low-power), score i32 (θ, 0..`lp_score_max`), samples u32 (traffic samples behind the score; it only grows along a STA's history, so the larger value is the newer record) (§8) |
| 0x10 | STEER_REQ | txn u32, sta 6, src_bssid 6, tgt_bssid 6, reason u8, rcpi u8, sta_flags u8, cur_rssi i8 |
| 0x11 | STEER_RESP | txn u32, status u8, hold_ms u16 |
| 0x12 | STEER_RESULT | txn u32, sta 6, outcome u8, btm_status u8 |
| 0x13 | ACK | msg_id u32 |
| 0x14 | STA_MONITOR_REQ | txn u32, sta 6, duration_ms u16, op_class u8, channel u8 (the STA's current channel, a hint) |
| 0x15 | STA_MONITOR_RESULT | txn u32, sta 6, bssid 6, rssi i8 (dBm), samples u16, age_ms u16 (since the last sample) |
| 0x16 | STA_MONITOR_STATUS | txn u32, sta 6, status u8: 0 measured (results in the same report), 1 not heard, 2 unsupported (no monitor, no driver API), 3 busy (watch table full), 4 failed (driver API error) |
| 0x17 | STA_ROAM | sta 6, threshold i8 (dBm, the STA's learned roaming threshold), events u32 (outcomes behind it; it only grows along a STA's history, so the larger value is the newer record) (§9) |
| 0x18 | CHALLENGE | nonce 16 bytes (random, from the kernel CSPRNG) |
| 0x19 | RESPONSE | nonce 16 bytes (copied from the CHALLENGE) |
| 0x1A | ENROLL_KEY | public key 32 bytes (Ed25519) of the AP asking to be enrolled (§10) |
| 0x1B | TRUST_REC | ap_id 6, public key 32, state u8 (1 trusted, 0 revoked), generation u32 (§10) |
| 0x1C | POLICY | the sender's steering settings, for the consistency check (§11): flags u16 (bit0 rssi_steering, bit1 load_balancing, bit2 band_steering, bit3 band_steer_6g, bit4 lp_no_steer, bit5 roam_thr_learn, bit6 lb_only_idle), rssi_low i8, rssi_hysteresis u8, rssi_min_target i8, band_steer_rssi i8, band_steer_6g_rssi i8, util_high u8, util_admit_max u8, lb_margin u8, score_model u8, steer_cooldown_s u16. Values outside a field's range are clamped |
| 0xFE | SIG | 64 bytes: Ed25519 signature (RFC 8032) of the header and the TLVs before it (§5) |
| 0xFF | AUTH | 16 bytes: HMAC-SHA256 truncated |

`caps` bits: FT 0x01, BTM 0x02, RRM-NR 0x04, RRM-Beacon 0x08, HT 0x10, VHT
0x20, HE 0x40, EHT 0x80, FT-over-DS 0x100.

`bssid_info` is the 802.11 Neighbor Report BSSID Information field. The
receiving AP sets the Mobility Domain bit itself, and only when its own MDID
matches the advertised one.

STA `flags`: 11k 0x01, 11v 0x02, 11r 0x04, idle 0x08, being steered 0x10,
low-power device 0x20 (§8).

`rcpi`: the target's RCPI as the STA measured it, taken from an 11k Beacon
Report (dBm = RCPI/2 − 110). 255 means it is not available.

## 4. Messages

| Type | Name | Delivery | TLVs | Period / trigger |
|---|---|---|---|---|
| 0x01 | HELLO | multicast | AP_INFO, POLICY, BSS_INFO* | `hello_interval_ms`; also sent right away after a new peer is seen |
| 0x02 | BSS_STATUS | multicast | (BSS_INFO, BSS_LOAD)* | `bss_status_interval_ms` |
| 0x03 | STA_STATUS | multicast | STA_ENTRY* (split over several messages if needed) | `sta_status_interval_ms` |
| 0x04 | RF_STATUS | multicast | RF_INFO* (one per operating channel) | `rf_status_interval_ms` |
| 0x05 | STA_EVENT | multicast | STA_EVENT | when a STA associates or disassociates |
| 0x06 | STA_CLASS | unicast, ACK_REQ | STA_CLASS*, STA_ROAM* | device class (§8) and learned roaming threshold (§9) of STAs: to every peer when a local STA's class changes; to the AP a STA just associated to (its STA_EVENT) when this AP knows the STA's class; all low-power records to a peer that appeared or restarted (several messages if needed) |
| 0x07 | TRUST | multicast | TRUST_REC* | enrollment trust table (§10): after a change, every 60 s, to a new peer; a welcome holds the sender's and the new AP's records |
| 0x10 | STEER_REQ | unicast, ACK_REQ | STEER_REQ | source AP asks the target AP to accept a STA |
| 0x11 | STEER_RESP | unicast, ACK_REQ | STEER_RESP | target AP's admission decision |
| 0x12 | STEER_RESULT | unicast, ACK_REQ | STEER_RESULT | source AP reports the outcome so the target frees its reservation: sent once a STEER_REQ went out, whatever the outcome (aborted included, e.g. the STA disconnected while the source waited for STEER_RESP, or that answer never arrived) |
| 0x13 | STA_MONITOR_REQ | multicast | STA_MONITOR_REQ | source AP asks every AP to measure a STA (§7) |
| 0x14 | STA_MONITOR_REPORT | unicast, ACK_REQ | STA_MONITOR_RESULT*, STA_MONITOR_STATUS | every AP that got the request answers once: at once if it cannot measure, else after the watch with one result per BSS that heard the STA; the status comes last |
| 0x20 | ACK | unicast | ACK | answers any message that has ACK_REQ set |
| 0x21 | BYE | multicast | — | graceful shutdown |
| 0x22 | CHALLENGE | unicast (to the frame's source on its port) | CHALLENGE | sent for a message whose (origin, `boot_id`) is not verified: an unknown origin, or a known one with another `boot_id` (§4) |
| 0x23 | RESPONSE | unicast (same way back) | RESPONSE | answer to a CHALLENGE, from the sender's current boot; also makes the sender re-send HELLO and BSS_STATUS |
| 0x24 | ENROLL_REQ | multicast | ENROLL_KEY | every 3 s from an AP not enrolled yet, signed with the announced key (§10) |

**Reliability:** a message with ACK_REQ is sent at most 4 times in total
(the first transmission and up to 3 retransmissions, 300 ms apart), always
with the same `msg_id`. The receiver ACKs every copy, duplicates
included, but processes a message only once.

**Liveness:** a peer is removed if nothing arrives from it within
`peer_timeout_ms`, or when it sends BYE. A remote BSS is dropped once it has
gone unadvertised for 3×`bss_status_interval_ms` + `hello_interval_ms`. When a
peer or BSS is removed, its entries leave the local hostapd neighbor database.

**Replay window:** for each peer, the receiver keeps a 64-entry sliding window
over `msg_id`, as IPsec does. A message is accepted if its `msg_id` is higher
than the highest seen so far, or falls inside the window without having been
seen. The window belongs to one verified `boot_id`; a message of any other
boot does not touch it.

**Liveness check (optional, `liveness_check 1`; off by default):** a receiver
adopts a peer's `boot_id` only through a fresh CHALLENGE / RESPONSE
exchange, so authenticated frames recorded earlier cannot be replayed,
whatever their `boot_id` and whether or not the receiver still knows the
peer. With the check off, a message with a new `boot_id` is adopted at once
(new peer, or restart), as is a BYE of any boot; every AP still answers a
CHALLENGE, so APs with and without the check work together.

1. A message arrives (valid AUTH) whose origin is unknown, or whose
   `boot_id` differs from the one verified for that origin. It is dropped
   and the receiver unicasts a CHALLENGE with a 16-byte random nonce to the
   frame's Ethernet source on the port it came in. At most one CHALLENGE per
   origin per 500 ms; up to 8 are outstanding (the oldest is reused). A BYE
   is dropped without a CHALLENGE.
2. Any AP that receives a CHALLENGE answers it with a RESPONSE carrying the
   nonce, from its current boot, without checking who asked (a RESPONSE is
   useless to anyone else). It then sends HELLO and BSS_STATUS again at
   once (at most once a second), since the challenger dropped them.
3. A RESPONSE whose nonce matches an outstanding CHALLENGE to that origin,
   less than 3 s old, verifies the RESPONSE's own `boot_id`: the peer entry
   is created (or, with another `boot_id`, the peer is logged as restarted),
   its window starts at the RESPONSE's `msg_id`, and the nonce is used up.

A reliable message dropped in step 1 is retransmitted (same `msg_id`) and
falls inside the new window. A restart or a new peer costs one round trip.

## 5. Authentication

With `key` configured, the sender sets the AUTH flag and appends the AUTH TLV
last. The MAC is `HMAC-SHA256(key, header ‖ TLVs before AUTH)` truncated to 16
bytes, with `body_len` already counting the AUTH TLV. A receiver with a key
drops every message without a valid AUTH TLV. A receiver without a key drops
every message that has the AUTH flag, so a key misconfiguration shows up
instead of failing silently.

A passphrase key (8 to 128 characters) is turned into a 32-byte key with
PBKDF2-HMAC-SHA256: salt `donghoa-arcp-key`, 100 000 iterations. A captured
frame then only allows slow offline guessing of the passphrase. The salt is
fixed because every AP must derive the same key; a `hex:` key of 32 random
bytes avoids guessing altogether.

The example key of `donghoa.conf.example` and the OpenWrt package is public
and is refused: the daemon does not start until it is replaced.

**Per-AP signatures (optional, recommended):** the group key above lets any
holder speak as any AP. With signatures each AP has its own Ed25519 key:

- `sign_seed hex:<64 hex>` (this AP's private seed, from `donghoa -g`) and
  one `peer_key <ap_id> hex:<64 hex>` line per AP allowed in the mesh (the
  same list can be installed on every AP: an AP's own line must match its
  seed, or it refuses to start). Both or neither, or the daemon refuses to
  start.
- The sender sets the SIG flag and appends the SIG TLV: an Ed25519
  signature of the header (with the final `body_len` and flags) and the
  TLVs before it. With `key` also set, AUTH follows and covers SIG too.
- A receiver with `peer_key` lines drops every message whose origin is not
  listed, or whose SIG does not verify under that origin's key (after the
  AUTH check, if a key is set). CHALLENGE and RESPONSE are signed like any
  message, so the liveness check also proves possession of the AP's key.
  A further copy of a message already accepted (another port, a
  retransmission) is recognised by the replay window and not verified again.
- Signatures must be canonical (S < L, RFC 8032 §5.1.7).

A stolen AP configuration then lets an attacker speak only as that AP;
removing its `peer_key` line on the other APs shuts it out. Cost: 67 bytes
per message, and per message one signature (sender) and one verification
(each receiver): about 0.4 ms each on x86-64 (`-O2`), more on small AP CPUs.

Instead of typing `sign_seed` and `peer_key` lines, keys can enroll
automatically (`enroll 1`, §10).

**Security defaults:** all of it is off unless configured: no `key` (no
HMAC), `liveness_check 0`, no signatures, no enrollment. The shipped
configurations show each option commented out.

**Replay:** within a boot the window (§4) refuses duplicates; across boots
and after a peer's removal, the liveness check (§4, when enabled) refuses
every recorded frame, because none can answer a fresh nonce.

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

## 7. AP-side measurement (STAs without 802.11k measurements)

A STA that does not support 802.11k, or does not answer a Beacon Request
while it is busy, cannot tell the source AP how well it hears the other
BSSes. The APs measure the reverse direction instead: the RSSI of the
STA's own frames, with a radiotap monitor interface (`air_monitor`) or the
driver's per-STA RSSI API (`sta_rssi_api`: the STA's MAC address is handed
to the Wi-Fi driver, which measures it; vendor-specific, see
`src/vendor_rssi.cpp`).

```
 STA          Source AP                        Every peer AP
  |  trigger -> MEASURE                                |
  |<- Beacon Request (if 11k; may be refused/ignored)  |
  |             |==== STA_MONITOR_REQ (multicast) ===> |  1. request
  |             |<--- REPORT: STATUS unsupported/busy  |     (at once, if it cannot measure)
  |~~ uplink data / probe requests ~~~~~~~~~~~~~~~~~~~>|  2. monitor / driver API, duration_ms
  |             |<--- REPORT: RESULT*, STATUS -------- |  3. measured or not heard
  |             |  4. evaluate when every AP waited for has answered (or at the timeout):
  |             |     11k level if any, else the AP-measured one
```

1. The source multicasts STA_MONITOR_REQ to every peer, and starts its own
   watch when one of its BSSes is a candidate.
2. Each AP measures the STA on its BSSes for `duration_ms`, with its monitor
   interfaces and/or the driver API.
3. Each AP answers exactly once with a STA_MONITOR_REPORT ending in a
   STA_MONITOR_STATUS: right away when it cannot measure (unsupported, busy,
   failed), otherwise after the watch (measured, with results; or not heard).
4. The source waits for the status of every peer that owns a candidate
   (others may answer; their results are kept). MEASURE ends as soon as all
   have answered, or at max(`beacon_req_timeout_ms`, `amon_duration_ms` +
   500 ms); a peer that has not answered by then counts as unable to measure
   (the request is not acknowledged, so a lost one ends this way).
- A peer credits samples to its BSSes on the frequency the frame was heard
  on (radiotap channel). A stock radio hears only its own channel: uplink
  data of STAs on that channel, and probe requests of scanning STAs.
- The result is uplink RSSI (STA → AP). The source compares it with its own
  uplink RSSI of the STA, so both sides are measured the same way. A
  configurable offset (`amon_rssi_offset`) can correct for TX-power
  asymmetry.
- A STA's own 11k report of a BSS always wins over a monitor result.

## 8. Low-power device classification

Every AP classifies its own STAs as low-power (IoT: sensors, cameras, smart
plugs) or normal from their traffic, and shares the result so the class
follows a STA from AP to AP instead of being learned again.

**Score.** Once per STA poll (`sta_poll_interval_ms`, 1 s by default) the AP
takes the STA's uplink rate *u* (hostapd `rx_bytes`) and downlink rate *d*
(`tx_bytes`) in bytes/s and keeps, over the connection,

    σ_d = sqrt( Σ (d_i − d̄_n)² / n )        (1)
    σ_u = sqrt( Σ (u_i − ū_n)² / n )        (2)
    S   = α(band) × σ_u / σ_d                (3)

α is `lp_alpha_2g` / `lp_alpha_5g` / `lp_alpha_6g` (×100). A low-power device
pushes its data up in bursts and receives little, so S > 1 adds one to the
STA's score θ and S ≤ 1 takes one away (θ stays in 0..`lp_score_max`). The STA
becomes low-power when θ > `lp_threshold` (δ) and normal again when θ <
δ − `lp_hysteresis`. S is not computed before `lp_min_samples` samples, nor
while neither rate varies, nor on a poll in which the STA moved no data (an
idle STA says nothing): θ is then unchanged. The idle poll still enters the
statistics; without this rule one old uplink burst (σ_u > 0) and no
downlink (σ_d = 0) would score S = ∞ on every idle poll.
Nor does S count while the STA's recent uplink rate (a moving average over
about 8 polls) is above `lp_max_mean_bps`: a large upload has the shape of a
sensor burst at a thousand times the volume. A STA that negotiated a PHY
ruled out by `lp_exclude_vht` / `lp_exclude_he` / `lp_exclude_eht` (defaults
1 / 0 / 1; HE stays allowed because Wi-Fi 6 IoT chips use it for TWT) is
never low-power; if it was, it is set back to normal at once, with its
sample count raised by one so that peers accept the correction.
Integer arithmetic: the running mean and variance use Welford's method; past
1024 samples n and the sum of squares are halved, which keeps the variance.

**Sharing.** There is no master AP; every AP keeps a table of class records
(STA, class, θ, samples, the AP that classified it).

1. A change of class of a local STA is sent in STA_CLASS to every peer.
2. When a STA associates to another AP (its STA_EVENT), an AP that has a
   record for it sends that AP the record. The new AP takes it over when it
   carries more samples than its own.
3. An AP that sees a new peer, or a peer with a new `boot_id`, sends it all its
   low-power records, so a restarted AP gets them back without re-learning,
   and the records that went from low-power back to normal, so a peer that
   missed that change does not keep the old flag. Other normal records are
   not sent.
4. Each STA_CLASS is acknowledged (ACK_REQ, §4).

**Use.** With `lp_no_steer` (default on), low-power STAs are left out of
automatic RSSI, band and load-balancing steering; a manual `STEER` still
works. STA_ENTRY carries the class as flag 0x20.

## 9. Per-STA roaming threshold

Each STA has its own RSSI roaming threshold, learned by the AP it is on
from the outcomes of its RSSI steers and from its own roams, within
`roam_thr_min`..`roam_thr_max` (−82..−65 dBm); `rssi_low` is the start
value. The value travels with the STA like its class: in STA_ROAM TLVs,
carried in STA_CLASS messages, versioned by `events` (a record replaces
another only with strictly more events).

1. A change of a local STA's threshold is sent to every peer.
2. When a STA associates to another AP, an AP holding its record sends it
   (with the class record).
3. A new or restarted peer gets every record with a learned threshold.
4. A live STA takes a received threshold over when it carries more events.

An AP that does not know STA_ROAM ignores it (unknown TLV).

## 10. Key enrollment

With `enroll 1`, each AP creates its own Ed25519 key (`seed_file`) and the
set of trusted keys is a **trust table** shared by all APs and kept in
`trust_file`. Details and diagrams: `docs/features/17-key-enrollment.md`.

**Trust table.** One record per ap_id: public key, state, generation (TLV
TRUST_REC). Records merge as last-writer-wins registers: the higher
generation wins; at equal generation "revoked" wins, then the larger key.
`peer_key` lines and the AP's own key enter at generation 0; an approval or
revocation takes the next generation of that ap_id.

**Enrollment request.** An AP that is not enrolled multicasts ENROLL_REQ
every 3 s: its public key (ENROLL_KEY), the message signed with that key.
A receiver that does not trust the origin checks that self-signature and
lists the request as pending (8 at most, forgotten after 60 s of silence);
a request with a revoked key is ignored. If the origin's key is already
trusted (the AP lost its table), the receiver welcomes it again.

**Approval.** `ENROLL approve <ap_id>` on any trusted AP records the pending
key as trusted (next generation), multicasts a **welcome** (a TRUST message
with the approver's own record and the new record) and then the whole
table.

**Welcome.** An AP not enrolled accepts one TRUST message from an untrusted
origin: it must hold the receiver's own key as trusted and the sender's own
trusted record, and be signed with the sender's key. The receiver merges it
and is enrolled from then on (kept in `trust_file`); `ENROLL init` marks the
first AP of a mesh as enrolled without a welcome.

**Spreading.** TRUST messages from a trusted origin are merged as soon as
their signature verifies (no liveness check: a replayed record loses the
merge). An AP whose table changed multicasts the whole table 0.3 s later;
every AP also sends it every 60 s and to a new or restarted peer. A peer
whose record turns to revoked is removed at once.

## 11. Configuration consistency

Each HELLO carries a POLICY TLV with the sender's steering settings. A
receiver compares them with its own, and compares its BSSes with the
advertised BSS_INFO of every BSS of the same SSID (its own and the peers'):

| Finding | Condition |
|---|---|
| `mdid_differs` | both BSSes advertise FT, with different mdid |
| `ft_one_sided` | only one of them advertises FT |
| `ft_over_ds_differs` | same mobility domain, FT over DS on one only |
| `security_differs` | the Security bit of bssid_info differs |
| `policy_differs` | any POLICY field differs |

Links of one AP MLD are not compared with each other. Findings are only
reported (log module `check`, the `CHECK` command); they change no
behaviour. A peer that sends no POLICY (an older version) is listed as
`policy_unknown` and is not counted as an issue.
