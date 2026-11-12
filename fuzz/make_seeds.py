#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Seed corpus for the fuzz targets: one valid example of each input kind,
so libFuzzer starts from inputs that get past the first length and magic
checks. Usage: make_seeds.py <out_dir>  (writes <out_dir>/<target>/*)."""
import hashlib
import hmac
import os
import struct
import sys

KEY = bytes(range(1, 33))


def tlv(t, value):
    return bytes([t]) + struct.pack(">H", len(value)) + value


def arcp(mtype, tlvs, auth):
    flags = 0x02 if auth else 0
    body_len = len(tlvs) + (19 if auth else 0)
    hdr = struct.pack(">HBBBBII6sH", 0x4152, 1, mtype, flags, 0, 7, 0x1234,
                      bytes.fromhex("020000000001"), body_len)
    msg = hdr + tlvs
    if auth:
        msg += tlv(0xFF, hmac.new(KEY, msg, hashlib.sha256).digest()[:16])
    return msg


def arcp_seeds():
    pattern = bytes((i * 37 + 11) & 0xFF for i in range(96))
    seeds = {"hello_empty": arcp(0x01, b"", False)}
    for t in list(range(0x01, 0x08)) + list(range(0x10, 0x1D)):
        for n in (0, 8, 32, 96):
            seeds["tlv_%02x_%d" % (t, n)] = arcp(0x02, tlv(t, pattern[:n]), n == 32)
    seeds["multi"] = arcp(0x02, tlv(0x01, pattern[:20]) + tlv(0x02, pattern[:40]) +
                          tlv(0x03, pattern[:8]), True)
    seeds["sig"] = arcp(0x01, tlv(0xFE, pattern[:64]), True)
    return seeds


def radiotap(fc0, fc1):
    # present: flags (1), channel (3), dbm signal (5)
    rt = struct.pack("<BBHI", 0, 0, 16, (1 << 1) | (1 << 3) | (1 << 5))
    rt += bytes([0x00, 0x00]) + struct.pack("<HH", 5180, 0x0140) + bytes([0xC4, 0x00])
    hdr = bytes([fc0, fc1]) + bytes(2) + bytes.fromhex("020000000001")
    hdr += bytes.fromhex("02000000aa01") + bytes.fromhex("020000000001") + bytes(2)
    return rt + hdr


def nlattr(t, value):
    a = struct.pack("<HH", len(value) + 4, t) + value
    return a + bytes((4 - len(a) % 4) % 4)


def station():
    rate = nlattr(5, struct.pack("<I", 1200))
    info = (nlattr(1, struct.pack("<I", 40)) + nlattr(7, struct.pack("<b", -60)) +
            nlattr(13, struct.pack("<b", -61)) + nlattr(16, struct.pack("<I", 100)) +
            nlattr(17, struct.pack("<II", 0x2, 0x2)) + nlattr(23, struct.pack("<Q", 1000)) +
            nlattr(24, struct.pack("<Q", 2000)) + nlattr(8, rate) + nlattr(14, rate))
    attrs = nlattr(6, bytes.fromhex("02000000aa01")) + nlattr(21, info)
    body = bytes([19, 1, 0, 0]) + attrs
    return struct.pack("<IHHII", 16 + len(body), 0x1c, 2, 1, 0) + body


def radio_seeds():
    return {
        "radiotap_data": b"\x00" + radiotap(0x88, 0x01),
        "radiotap_probe": b"\x00" + radiotap(0x40, 0x00),
        "nl_station": b"\x01" + station(),
        "opclasses": b"\x02" + bytes([81, 81, 83, 84, 115, 116, 128, 131, 134]),
    }


STATUS = ("state=ENABLED\nfreq=5180\nchannel=36\nieee80211n=1\nieee80211ac=1\nieee80211ax=1\n"
          "max_txpower=20\nbss[0]=wlan0\nbssid[0]=02:00:00:00:01:00\nssid[0]=Home\n"
          "num_sta[0]=2\nchan_util_avg=120\nieee80211be=1\nmld_addr[0]=02:00:00:00:0f:00\n"
          "mld_id[0]=0\nmld_link_id[0]=1\nvht_oper_chwidth=1\n")
STA = ("02:00:00:00:aa:01\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][HT][VHT][HE]\nrx_bytes=1000\n"
       "tx_bytes=2000\ninactive_msec=40\nsignal=-61\nrx_rate_info=1200\ntx_rate_info=1200\n"
       "connected_time=10\next_capab=0000080000000040\nAKMSuiteSelector=000fac-8\n"
       "peer_addr[0]=02:00:00:00:aa:11\nmax_simul_links=1\nsupp_op_classes=51515354737480\n")
BCN = (bytes([115, 36]) + bytes(8) + (50).to_bytes(2, "little") + bytes([0, 100, 0]) +
       bytes.fromhex("020000000100") + bytes(5))
CONFIG = ("iface eth0\nap_id 02:00:00:00:00:01\nbss wlan0 mdid=1234 max_sta=32\n"
          "rssi_low -75\nscore_model 1\nsim_port 4000\nsim_peer 127.0.0.1:4001\n"
          "sign_seed hex:" + "11" * 32 + "\npeer_key 02:00:00:00:00:02 hex:" + "22" * 32 +
          "\nenroll 1\nlog_debug steer\nrl_roam 1\n")
TRUST = ("# trust\nenrolled 1\ntrusted 02:00:00:00:00:01 "
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a 0\n"
         "revoked 02:00:00:00:00:02 "
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c 3\n")


def text_seeds():
    return {
        "status": b"\x00" + STATUS.encode(),
        "sta": b"\x01" + STA.encode(),
        "btm": b"\x02" + b"BSS-TM-RESP 02:00:00:00:aa:01 dialog_token=1 status_code=0 "
                         b"bss_termination_delay=0 target_bssid=02:00:00:00:01:00",
        "beacon": b"\x03" + BCN.hex().encode(),
        "config": b"\x04" + CONFIG.encode(),
        "trust": b"\x05" + TRUST.encode(),
    }


def main():
    out = sys.argv[1]
    for target, seeds in (("arcp", arcp_seeds()), ("radio", radio_seeds()), ("text", text_seeds())):
        d = os.path.join(out, target)
        os.makedirs(d, exist_ok=True)
        for name, data in seeds.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)


if __name__ == "__main__":
    main()
