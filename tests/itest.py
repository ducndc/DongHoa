#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end test: real donghoa processes over the UDP "sim" L2 transport,
each driving a mock hostapd. No root privileges required.

Scenarios:
  1. discovery + authenticated BSS exchange + 11k neighbor DB population
  2. an AP with the wrong key is never accepted as a peer
  3. RSSI-triggered roam: 11k beacon report -> STEER_REQ/RESP -> 11v BTM -> roam
     (the STA supports passive beacon reports only: active must fall back)
  4. load balancing: overloaded BSS offloads an idle STA to a quiet peer
  5. air monitor: a STA without 802.11k is measured by a peer's monitor
     (radiotap frames injected over UDP) and steered there
  6. peer departure (BYE) removes the neighbor entries
  7. band steering 2.4 -> 5 GHz on AP1's own sibling BSS: a STA that
     advertises only 2.4 GHz operating classes is never measured or
     steered, a dual-band one is steered, and one that advertises nothing
     and never reports a 5 GHz level backs off exponentially
  8. 6 GHz on AP1's own 6 GHz BSS: a tri-band WPA3 STA goes 2.4 -> 6 GHz, a
     tri-band WPA2-PSK STA goes to 5 GHz instead (6 GHz needs WPA3/OWE), a
     5 GHz STA advertising 6 GHz goes 5 -> 6 GHz, and a 5 GHz STA without
     6 GHz operating classes is left alone

Environment:
  DONGHOA_BIN, DONGHOA_CLI_BIN  commands to run instead of ./donghoa and
      ./donghoa_cli, e.g. "<sdk>/lib/ld-musl-x86_64.so.1 <pkgdir>/donghoa"
      to run binaries built with the OpenWrt SDK
  DONGHOA_ITEST_EXTRA  extra config lines for every AP, ";"-separated
  DONGHOA_ITEST_DIR    directory for configs and logs (default: a new
      temporary directory); logs are kept when it is set. Keep the path
      short: the hostapd sockets inside it must fit in 108 bytes
  DONGHOA_KEEP_LOGS    keep the temporary directory after a pass

Each AP log gets "=== Sn" markers at the start of every scenario, and
merged.log interleaves the three AP logs by their monotonic timestamps.
"""
import os
import random
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mock_hostapd import Sta, World  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DONGHOA = shlex.split(os.environ.get("DONGHOA_BIN", os.path.join(ROOT, "donghoa")))
CLI = shlex.split(os.environ.get("DONGHOA_CLI_BIN", os.path.join(ROOT, "donghoa_cli")))
STA_MAC = "aa:bb:cc:dd:ee:01"
STA2_MAC = "aa:bb:cc:dd:ee:02"  # no 802.11k
B1, B2 = "02:00:00:00:01:00", "02:00:00:00:02:00"
B1G = "02:00:00:00:01:01"  # AP1's 2.4 GHz BSS
STA3_MAC = "aa:bb:cc:dd:ee:03"  # 2.4 GHz only
STA4_MAC = "aa:bb:cc:dd:ee:04"  # 2.4 + 5 GHz
STA5_MAC = "aa:bb:cc:dd:ee:05"  # no Supported Operating Classes, no 5 GHz level
B6 = "02:00:00:00:01:02"  # AP1's 6 GHz BSS
STA6_MAC = "aa:bb:cc:dd:ee:06"  # tri-band, SAE, on 2.4 GHz
STA7_MAC = "aa:bb:cc:dd:ee:07"  # tri-band, FT-PSK, on 2.4 GHz
STA8_MAC = "aa:bb:cc:dd:ee:08"  # tri-band, SAE, on 5 GHz
STA9_MAC = "aa:bb:cc:dd:ee:09"  # no operating classes, SAE, on 5 GHz
SAE = "00-0f-ac-8"
TRI = "5151737c83"  # current 81; 81, 115, 124, 131
# Extra config lines for every AP, ";"-separated, e.g. "score_model 1".
EXTRA = os.environ.get("DONGHOA_ITEST_EXTRA", "").replace(";", "\n")


def wait_for(pred, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError("timeout waiting for " + what)


def cli(sock, *cmd):
    r = subprocess.run(CLI + [sock] + list(cmd), capture_output=True, text=True, timeout=5)
    return r.stdout


def write_cfg(path, ap_id, name, hdir, ctrl, port, peers, key, extra=""):
    with open(path, "w") as f:
        f.write(f"""name {name}
ap_id {ap_id}
sim_port {port}
{"".join(f"sim_peer {p}{chr(10)}" for p in peers)}hostapd_ctrl_dir {hdir}
ctrl_socket {ctrl}
bss {name}-wl0 mdid=a1b2
key {key}
hello_interval_ms 300
bss_status_interval_ms 500
sta_status_interval_ms 1000
rf_status_interval_ms 1000
sta_poll_interval_ms 200
peer_timeout_ms 2000
steer_cooldown_ms 1500
beacon_req_timeout_ms 800
lb_interval_ms 1000
{extra}""")


def mark(logs, text):
    """Scenario marker in every AP log, in the daemons' own time format
    (CLOCK_MONOTONIC seconds, the clock behind time.monotonic() on Linux)."""
    line = f"{time.monotonic():.3f} [---] itest: === {text}\n"
    for log in logs:
        log.write(line)
        log.flush()


def merge_logs(tmp, n):
    """Interleave ap1..apN logs by timestamp into merged.log."""
    rows = []
    for i in range(1, n + 1):
        try:
            lines = open(os.path.join(tmp, f"ap{i}.log")).read().splitlines()
        except OSError:
            continue
        for seq, line in enumerate(lines):
            try:
                ts = float(line.split(" ", 1)[0])
            except ValueError:
                continue
            if "itest: ===" in line:
                if i != 1:
                    continue  # one copy of each marker
                rows.append((ts, -1, seq, "\n" + line))
            else:
                rows.append((ts, i, seq, f"ap{i} | {line}"))
    rows.sort()
    with open(os.path.join(tmp, "merged.log"), "w") as f:
        for r in rows:
            f.write(r[3] + "\n")


def radiotap_data(ta, bssid, freq, signal):
    """Uplink data frame (ToDS) as a monitor interface delivers it."""
    rt = struct.pack("<BBHI", 0, 0, 15, 0x2a)                # flags, channel, dBm signal
    rt += struct.pack("<BxHHb", 0, freq, 0x0100, signal)
    mac = lambda m: bytes.fromhex(m.replace(":", ""))
    return rt + bytes([0x08, 0x01, 0, 0]) + mac(bssid) + mac(ta) + mac(bssid) + bytes(2)


def main():
    tmp = os.environ.get("DONGHOA_ITEST_DIR")
    if tmp:
        os.makedirs(tmp, exist_ok=True)
    else:
        tmp = tempfile.mkdtemp(prefix="donghoa-itest-")
    base = random.randint(20000, 50000)
    ports = [base, base + 1, base + 2]
    mon_port = base + 10  # AP2's air monitor input
    world = World()
    procs = []
    ok = False
    try:
        h1, h2, h3 = (os.path.join(tmp, f"hostapd{i}") for i in (1, 2, 3))
        ap1 = world.add_bss(h1, "ap1-wl0", B1, "home", 5180, 36, util=40)
        ap2 = world.add_bss(h2, "ap2-wl0", B2, "home", 5745, 149, util=25)
        ap1g = world.add_bss(h1, "ap1-wl1", B1G, "home", 2437, 6)
        world.add_bss(h1, "ap1-wl2", B6, "home", 5955, 1)
        world.add_bss(h3, "ap3-wl0", "02:00:00:00:03:00", "home", 2437, 6)
        sta = Sta(STA_MAC, -82, {B2: (124, 149, -55)}, rrm={0})  # passive only
        ap1.stas[STA_MAC] = sta
        world.start()

        socks = [os.path.join(tmp, f"ctrl{i}") for i in (1, 2, 3)]
        cfgs = [
            ("02:00:00:00:00:01", "ap1", h1, socks[0], ports[0], [ports[1], ports[2]], "s3cret-mesh-key"),
            ("02:00:00:00:00:02", "ap2", h2, socks[1], ports[1], [ports[0], ports[2]], "s3cret-mesh-key"),
            ("02:00:00:00:00:03", "ap3", h3, socks[2], ports[2], [ports[0], ports[1]], "WRONG-mesh-key"),
        ]
        logs = []
        for i, c in enumerate(cfgs):
            cfg = os.path.join(tmp, f"ap{i + 1}.conf")
            mon = f"air_monitor_sim {mon_port}\n" if i == 1 else ""
            if i == 0:
                mon = "bss ap1-wl1 mdid=a1b2\nbss ap1-wl2 mdid=a1b2\n"
            write_cfg(cfg, *c, extra=mon + EXTRA)
            path = os.path.join(tmp, f"ap{i + 1}.log")
            open(path, "w").close()
            log = open(path, "a")
            logs.append(log)
            procs.append(subprocess.Popen(DONGHOA + ["-c", cfg, "-d"], stderr=log))

        mark(logs, "S1 discovery, BSS/load exchange, 11k neighbor DB")
        wait_for(lambda: B2 in cli(socks[0], "PEERS") and "util=" in cli(socks[0], "PEERS"),
                 5, "AP1 to learn AP2's BSS and load")
        wait_for(lambda: B2 in ap1.neighbors and B1 in ap2.neighbors, 5,
                 "neighbor DBs to be populated")
        nr = ap1.neighbors[B2].split("nr=")[1]
        bssid_info = int.from_bytes(bytes.fromhex(nr[12:20]), "little")
        assert bssid_info & 0x400, "Mobility Domain bit expected (same MDID)"
        # Run-time log control
        out = cli(socks[2], "LOG", "warn")
        assert "steer=warn" in out and "msg=warn" in out, out
        out = cli(socks[2], "LOG", "debug", "steer", "amon")
        assert "steer=debug" in out and "amon=debug" in out and "msg=warn" in out, out
        assert cli(socks[2], "LOG", "loud").startswith("FAIL"), "bad level must fail"
        cli(socks[2], "LOG", "debug")
        print("PASS 1: discovery, BSS/load exchange, 11k neighbor DB (FT MD bit set)")

        mark(logs, "S2 AP with wrong key is not accepted")
        time.sleep(1.0)
        assert "02:00:00:00:00:03" not in cli(socks[0], "PEERS"), "AP3 must be rejected"
        assert "02:00:00:00:03:00" not in ap1.neighbors
        print("PASS 2: AP with wrong key is not accepted")

        mark(logs, "S3 RSSI roam AP1 -> AP2 (11k passive fallback, STEER_REQ/RESP, BTM)")
        # RSSI roam AP1 -> AP2 (STA was 'present' before attach: send event)
        ap1.event("AP-STA-CONNECTED " + STA_MAC)
        wait_for(lambda: any(t[0] == B1 and t[2] == B2 for t in world.btm_log), 10,
                 "BTM request from AP1 towards AP2")
        wait_for(lambda: STA_MAC in ap2.stas, 3, "STA to roam to AP2")
        btm = [t for t in world.btm_log if t[0] == B1][0][3]
        assert "pref=1" in btm and "abridged=1" in btm and ",0301ff" in btm, btm
        logs[0].flush()
        logs[1].flush()
        wait_for(lambda: "finished: success" in open(logs[0].name).read(), 3,
                 "AP1 to record steering success")
        l2txt = open(logs[1].name).read()
        assert "steer-in request" in l2txt and "accept" in l2txt
        # Active (mode 01) refused by "hostapd", then passive (00) with >= 120 TU
        reqs = [c.split()[2] for c in ap1.cmd_log if c.startswith("REQ_BEACON " + STA_MAC)]
        assert reqs and reqs[0][12:14] == "01", reqs
        assert any(r[12:14] == "00" and int.from_bytes(bytes.fromhex(r[8:12]), "little") >= 120
                   for r in reqs), reqs
        assert "passive beacon reports" in open(logs[0].name).read()
        # 802.11k/v dump (log module rrm, debug): commands and events, raw + decoded
        l1 = open(logs[0].name).read()
        for want in ("rrm: ap1-wl0 TX REQ_BEACON " + STA_MAC, "11k beacon request -> " + STA_MAC,
                     "rrm: ap1-wl0 RX BEACON-RESP-RX " + STA_MAC, "11k beacon report <- " + STA_MAC,
                     "11v BTM request -> " + STA_MAC, "11v BTM response <- " + STA_MAC + ": status 0 (accept)",
                     "11k neighbor report entry " + B2):
            assert want in l1, "rrm dump line missing: " + want
        print("PASS 3: RSSI roam: passive beacon report (active refused) -> STEER_REQ/RESP -> BTM -> roam")

        mark(logs, "S4 load balancing: busy AP2 offloads the STA to AP1")
        # Load balancing: AP2 overloaded, idle STA has a decent AP1 option
        sta.signal = -58
        sta.view[B1] = (115, 36, -60)
        ap1.util = 30
        ap2.util = 230  # ~90 %
        n_btm = len(world.btm_log)
        wait_for(lambda: len(world.btm_log) > n_btm and world.btm_log[-1][0] == B2
                 and world.btm_log[-1][2] == B1, 12, "load-balancing BTM from AP2 to AP1")
        wait_for(lambda: STA_MAC in ap1.stas, 3, "STA to move back to AP1")
        wait_for(lambda: "reason load" in open(logs[1].name).read(), 2, "load reason logged")
        print("PASS 4: load balancing offloads idle STA from busy AP2 to AP1")

        mark(logs, "S5 air monitor: STA without 11k measured by AP2's monitor")
        # Air monitor: STA2 has no 802.11k (REQ_BEACON fails), so only
        # AP2's monitor can tell AP1 how well AP2 hears it.
        ap2.util = 25
        sta2 = Sta(STA2_MAC, -83, {}, rrm=False)
        stop_inject = threading.Event()

        def inject():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            frame = radiotap_data(STA2_MAC, B1, 5745, -58)
            while not stop_inject.is_set():
                s.sendto(frame, ("127.0.0.1", mon_port))
                time.sleep(0.05)
            s.close()

        injector = threading.Thread(target=inject, daemon=True)
        injector.start()
        with world.lock:
            ap1.add_sta(sta2)
        try:
            wait_for(lambda: any(t[0] == B1 and t[1] == STA2_MAC and t[2] == B2
                                 for t in world.btm_log), 15, "BTM for STA2 towards AP2")
            wait_for(lambda: STA2_MAC in ap2.stas, 3, "STA2 to roam to AP2")
        finally:
            stop_inject.set()
        assert any(c.startswith("REQ_BEACON " + STA2_MAC) for c in ap1.cmd_log)
        for log in logs:
            log.flush()
        assert "asks to measure " + STA2_MAC in open(logs[1].name).read()
        assert STA2_MAC + " heard by " + B2 in open(logs[0].name).read()
        print("PASS 5: air monitor: STA without 11k measured by peer's monitor and steered")

        mark(logs, "S6 AP2 sends BYE")
        # AP2 leaves gracefully -> AP1 drops its neighbor entry
        procs[1].send_signal(signal.SIGTERM)
        procs[1].wait(timeout=5)
        wait_for(lambda: B2 not in ap1.neighbors, 3, "REMOVE_NEIGHBOR for AP2")
        assert B2 not in cli(socks[0], "PEERS")
        print("PASS 6: BYE removes peer and its neighbor report entry")

        if "score_model 1" in EXTRA:
            # The mock BSSes are 20 MHz: with the throughput model a band
            # change is not the required tput_gain_pct gain, so no band steer.
            print("SKIP 7, 8: band steering scenarios assume score_model 0 (20 MHz mock BSSes)")
            ok = True
            return 0
        mark(logs, "S7 band steering 2.4 -> 5 GHz checks the STA's operating classes")
        # All three sit close to AP1 on 2.4 GHz (band steering trigger).
        # Each "sees" AP1's 5 GHz BSS, so only the band check keeps STA3
        # from being measured and steered.
        sta3 = Sta(STA3_MAC, -40, {B1: (115, 36, -45)}, op_classes="515152")
        sta4 = Sta(STA4_MAC, -40, {B1: (115, 36, -50)}, op_classes="5151737c")
        sta5 = Sta(STA5_MAC, -40, {})
        t0 = time.monotonic()
        with world.lock:
            for s in (sta3, sta4, sta5):
                ap1g.add_sta(s)
        wait_for(lambda: any(t[0] == B1G and t[1] == STA4_MAC and t[2] == B1 for t in world.btm_log),
                 5, "band-steering BTM for dual-band STA4 to AP1's 5 GHz BSS")
        wait_for(lambda: STA4_MAC in ap1.stas, 3, "STA4 to move to 5 GHz")
        # cooldown 1500 ms: 3000 ms after the first empty measurement,
        # 6000 ms after the second
        wait_for(lambda: "sta " + STA5_MAC + ": no higher-band level (2 in a row), next band steer in 6000 ms"
                 in open(logs[0].name).read(), 10, "band backoff to grow for STA5")
        assert time.monotonic() - t0 > 3.0, "second band attempt came before the backoff"
        stas = cli(socks[0], "STAS")
        line = {m: next((l for l in stas.splitlines() if l.startswith("sta " + m)), "")
                for m in (STA3_MAC, STA4_MAC, STA5_MAC)}
        assert "bands=2g(single) adv=2g seen=2g" in line[STA3_MAC], stas
        assert "bands=2g,5g(dual) adv=2g,5g seen=2g,5g" in line[STA4_MAC], stas
        assert "bands=2g(unknown) adv=- seen=2g" in line[STA5_MAC], stas
        assert not any(c.startswith("REQ_BEACON " + STA3_MAC) for c in ap1g.cmd_log), \
            "2.4 GHz-only STA must not be measured for band steering"
        assert not any(t[1] == STA3_MAC for t in world.btm_log), "2.4 GHz-only STA must not be steered"
        print("PASS 7: band steering skips a 2.4 GHz-only STA, steers a dual-band one, backs off when unmeasured")

        mark(logs, "S8 6 GHz: 2.4 -> 6 (WPA3), WPA2-PSK kept off 6 GHz, 5 -> 6, no 6 GHz classes")
        both = {B6: (131, 1, -48), B1: (115, 36, -52)}  # 6 GHz scores higher (bonus 8 vs 5)
        sta6 = Sta(STA6_MAC, -40, both, op_classes=TRI, akm=SAE)
        sta7 = Sta(STA7_MAC, -40, both, op_classes=TRI)
        sta8 = Sta(STA8_MAC, -45, {B6: (131, 1, -50)}, op_classes="73517376" "7c83", akm=SAE)
        sta9 = Sta(STA9_MAC, -45, {B6: (131, 1, -50)}, akm=SAE)
        n_btm = len(world.btm_log)
        with world.lock:
            ap1g.add_sta(sta6)
            ap1g.add_sta(sta7)
            ap1.add_sta(sta8)
            ap1.add_sta(sta9)
        btm_to = lambda mac, src: [t[2] for t in world.btm_log[n_btm:] if t[1] == mac and t[0] == src]
        wait_for(lambda: B6 in btm_to(STA6_MAC, B1G), 5, "STA6 band-steered 2.4 -> 6 GHz")
        wait_for(lambda: B1 in btm_to(STA7_MAC, B1G), 5, "WPA2-PSK STA7 band-steered to 5 GHz")
        wait_for(lambda: B6 in btm_to(STA8_MAC, B1), 5, "STA8 band-steered 5 -> 6 GHz")
        assert B6 not in btm_to(STA7_MAC, B1G), "WPA2-PSK STA must not be sent to 6 GHz"
        stas = cli(socks[0], "STAS")
        line7 = next((l for l in stas.splitlines() if l.startswith("sta " + STA7_MAC)), "")
        assert "adv=2g,5g,6g" in line7 and "no6g=wpa2-psk" in line7, stas
        time.sleep(1.0)
        assert not any(t[1] == STA9_MAC for t in world.btm_log), "STA9 has no 6 GHz classes: no 5 -> 6 steer"
        assert not any(c.startswith("REQ_BEACON " + STA9_MAC) for c in ap1.cmd_log), \
            "STA9 must not be measured for 5 -> 6 GHz"
        print("PASS 8: 6 GHz: 2.4 -> 6 (WPA3), WPA2-PSK to 5 GHz instead, 5 -> 6, none without 6 GHz classes")
        ok = True
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
        world.stop()
        merge_logs(tmp, len(procs))
        if ok and not os.environ.get("DONGHOA_KEEP_LOGS") and not os.environ.get("DONGHOA_ITEST_DIR"):
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print("logs kept in", tmp)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
