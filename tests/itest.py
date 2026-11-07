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
  9. Wi-Fi 7 MLO: AP1's AP MLD (link 0 on 5 GHz, link 1 on 2.4 GHz) and an
     MLD STA on both links: one STA entry with per-link RSSI, no band
     steering onto its own link, no roam while one link is still good, and
     when every link is weak a roam to another BSS, never to its own AP MLD

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
BMLD = "02:00:00:00:01:1f"  # AP1's AP MLD address
BM0, BM1 = "02:00:00:00:01:10", "02:00:00:00:01:11"  # its links: 0 = 5 GHz ch 44, 1 = 2.4 GHz ch 11
STA10_MAC = "aa:bb:cc:dd:ee:10"  # MLD STA (MLD address)
STA11_MAC = "aa:bb:cc:dd:ee:11"  # IoT sensor: bursty uplink, little downlink
STA12_MAC = "aa:bb:cc:dd:ee:12"  # phone: bursty downlink
STA13_MAC = "aa:bb:cc:dd:ee:13"  # VHT/HE phone with sensor-shaped traffic: never low-power
STA14_MAC = "aa:bb:cc:dd:ee:14"  # Wi-Fi 6 (HE only) sensor: HE alone does not rule it out
STA16_MAC = "aa:bb:cc:dd:ee:16"  # no 802.11k: measured by AP1's driver RSSI API (simulated)
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
lp_min_samples 3
lp_threshold 8
lp_hysteresis 2
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


def sensor_traffic(n):
    return (4000, 200) if n % 5 == 0 else (40, 20)


def phone_traffic(n):
    return (3000, 900000) if n % 5 == 0 else (200, 4000)


def scenario_low_power(world, procs, logs, socks, tmp, ap1, ap2):
    """S10: low-power (IoT) classification from traffic behaviour; the class
    goes to the peers, follows the STA to another AP, survives a peer
    restart, and keeps automatic steering off the device."""
    mark(logs, "S10 low-power device classification, shared between APs")
    ap2_cfg = os.path.join(tmp, "ap2.conf")
    procs[1] = subprocess.Popen(DONGHOA + ["-c", ap2_cfg, "-d"], stderr=logs[1])  # AP2 left in S6
    wait_for(lambda: "02:00:00:00:00:02" in cli(socks[0], "PEERS"), 5, "AP2 to rejoin")
    line = lambda sock, mac: next((l for l in cli(sock, "STAS").splitlines() if l.startswith("sta " + mac)), "")
    sensor = Sta(STA11_MAC, -50, {B2: (124, 149, -55)}, traffic=sensor_traffic)
    phone = Sta(STA12_MAC, -50, {}, traffic=phone_traffic)
    # Same bursty-up/quiet-down shape as the sensor, but VHT/HE: a real
    # transfer or background chatter from capable hardware, never low-power.
    capable = Sta(STA13_MAC, -50, {}, traffic=sensor_traffic, phy_caps=["VHT", "HE"])
    he_sensor = Sta(STA14_MAC, -50, {}, traffic=sensor_traffic, phy_caps=["HE"])
    with world.lock:
        ap1.add_sta(sensor)
        ap1.add_sta(phone)
        ap1.add_sta(capable)
        ap1.add_sta(he_sensor)
    # lp_min_samples 3 + lp_threshold 8 + 1 polls of 200 ms
    wait_for(lambda: "class=low-power" in line(socks[0], STA11_MAC), 6, "AP1 to classify the sensor")
    wait_for(lambda: "class=low-power" in line(socks[0], STA14_MAC), 2, "AP1 to classify the HE-only sensor")
    wait_for(lambda: STA11_MAC + " class=low-power" in cli(socks[1], "DEVCLASS"), 3,
             "AP2 to receive the sensor's class")
    time.sleep(1.0)
    assert "class=normal lp_score=0/8" in line(socks[0], STA12_MAC), line(socks[0], STA12_MAC)
    assert STA12_MAC not in cli(socks[1], "DEVCLASS"), "an unchanged (normal) class is not sent"
    assert "class=normal" in line(socks[0], STA13_MAC), line(socks[0], STA13_MAC)
    assert STA13_MAC not in cli(socks[1], "DEVCLASS"), "VHT/HE overrides a sensor-shaped traffic score"
    with world.lock:
        ap1.remove_sta(capable)
    # Weak signal, better AP in view: a normal STA would roam; this one is low-power.
    n_btm = len(world.btm_log)
    sensor.signal = -85
    time.sleep(3.0)
    assert not any(t[1] == STA11_MAC for t in world.btm_log[n_btm:]), "low-power STA must not be steered"
    # AP2 restarts without BYE: AP1 sends it the low-power records again.
    # While AP2 is down the HE sensor turns out VHT-capable: AP1 corrects it
    # to normal, and the correction must reach AP2 in the rejoin sync.
    procs[1].kill()
    procs[1].wait(timeout=3)
    # Only after AP1 has dropped AP2: no broadcast or retransmission of the
    # correction can reach it, only the rejoin sync.
    wait_for(lambda: "02:00:00:00:00:02" not in cli(socks[0], "PEERS"), 5, "AP1 to drop AP2")
    he_sensor.phy_caps.append("VHT")
    wait_for(lambda: "class=normal" in line(socks[0], STA14_MAC), 2, "AP1 to correct the VHT STA")
    procs[1] = subprocess.Popen(DONGHOA + ["-c", ap2_cfg, "-d"], stderr=logs[1])
    wait_for(lambda: STA11_MAC + " class=low-power" in cli(socks[1], "DEVCLASS"), 6,
             "restarted AP2 to get the class back from AP1")
    wait_for(lambda: STA14_MAC + " class=normal" in cli(socks[1], "DEVCLASS"), 2,
             "restarted AP2 to get the correction back to normal")
    devclass = cli(socks[1], "DEVCLASS")
    dev = next(l for l in devclass.splitlines() if STA11_MAC in l)
    assert "from=02:00:00:00:00:01" in dev, dev
    assert STA12_MAC not in devclass, "the sync skips plain normal records"
    with world.lock:
        ap1.remove_sta(he_sensor)
    # The sensor roams to AP2 and goes quiet: AP2 cannot learn it again, it
    # knows the class at once.
    sensor.traffic = None
    sensor.tput_bytes = 0
    world.move(STA11_MAC, B1, B2)
    wait_for(lambda: "class=low-power" in line(socks[1], STA11_MAC), 2, "AP2 to treat the sensor as low-power")
    wait_for(lambda: any(l.startswith("remote " + STA11_MAC) and "class=low-power" in l
                         for l in cli(socks[0], "STAS").splitlines()), 3,
             "AP1 to see the low-power flag in AP2's STA_STATUS")
    logs[0].flush()
    assert ("sta " + STA11_MAC + " joined AP 02:00:00:00:00:02: sending its class"
            in open(logs[0].name).read()), "AP1 answers the new association with the class"
    with world.lock:
        ap1.remove_sta(STA12_MAC)
    print("PASS 10: low-power classification (sensor yes, phone no, VHT no, HE-only yes), shared with "
          "peers, kept across roam and peer restart, corrections synced, not steered")


def scenario_driver_rssi(world, procs, logs, socks, tmp, ap1, ap2):
    """S11: a STA without 802.11k on AP2. AP2 multicasts STA_MONITOR_REQ;
    AP1 measures with the driver's per-STA RSSI API (simulated through the
    sta_rssi_sim file) and always answers with a STA_MONITOR_STATUS."""
    mark(logs, "S11 driver per-STA RSSI API: every AP answers, measured or not")
    sim = os.path.join(tmp, "rssi_ap1")
    if os.path.exists(sim):
        os.remove(sim)  # no file: AP1's driver has no such API
    sta = Sta(STA16_MAC, -85, {}, rrm=False)
    with world.lock:
        ap2.add_sta(sta)
    # Step 3, cannot measure: AP1 says so at once, and AP2 evaluates
    # without waiting for the monitor timeout; nothing to steer to.
    wait_for(lambda: STA16_MAC + ": AP 02:00:00:00:00:01 unsupported" in open(logs[1].name).read(), 8,
             "AP1 to answer 'unsupported' to AP2's measurement request")
    assert not any(t[1] == STA16_MAC for t in world.btm_log), "nothing measured, nothing to steer"
    log2 = open(logs[1].name).read().split("=== S11")[-1]
    assert "no measurement answer from AP" not in log2, "an answer arrived, no timeout"
    # Step 2, the driver measures the STA: AP1 reports it, AP2 steers.
    with open(sim + ".tmp", "w") as f:
        f.write("ap1-wl0 %s -50\n" % STA16_MAC)
    os.replace(sim + ".tmp", sim)
    wait_for(lambda: any(t[0] == B2 and t[1] == STA16_MAC and t[2] == B1 for t in world.btm_log), 20,
             "BTM for STA16 towards AP1 after the driver measured it")
    wait_for(lambda: STA16_MAC in ap1.stas, 3, "STA16 to roam to AP1")
    for log in logs:
        log.flush()
    assert STA16_MAC + " heard by " + B1 + " (AP 02:00:00:00:00:01): -50 dBm" in open(logs[1].name).read()
    assert STA16_MAC + ": AP 02:00:00:00:00:01 measured" in open(logs[1].name).read()
    assert "asks to measure " + STA16_MAC in open(logs[0].name).read()
    with world.lock:
        ap1.remove_sta(STA16_MAC)
    print("PASS 11: driver RSSI API: multicast request, 'unsupported' answered at once, "
          "measured STA steered to the AP that heard it")


STA18_MAC = "aa:bb:cc:dd:ee:18"  # S13: weak signal, but idle (old frame) until it sends again


def scenario_idle_signal(world, procs, logs, socks, tmp, ap1, ap2):
    """S13: hostapd's signal is that of the STA's last frame. An idle STA
    (large inactive_msec) keeps an old weak value: it must not count on
    every poll and trigger a roam. Once the STA sends again, it does."""
    mark(logs, "S13 stale signal of an idle STA does not trigger a roam")
    sta = Sta(STA18_MAC, -85, {B2: (124, 149, -55)}, rrm={0}, inactive_ms=30000)
    with world.lock:
        ap1.add_sta(sta)
    time.sleep(5.0)  # rssi_low_count 3 polls of 200 ms, many times over
    log1 = open(logs[0].name).read().split("=== S13")[-1]
    assert STA18_MAC + " start: reason rssi" not in log1, "idle STA steered on a stale sample"
    assert not any(t[1] == STA18_MAC for t in world.btm_log)
    sta.inactive_ms = 100  # it sends again, still weak
    wait_for(lambda: any(t[0] == B1 and t[1] == STA18_MAC and t[2] == B2 for t in world.btm_log), 10,
             "BTM for STA18 once its signal is fresh")
    wait_for(lambda: STA18_MAC in ap2.stas, 3, "STA18 to roam to AP2")
    with world.lock:
        ap2.remove_sta(STA18_MAC)
    print("PASS 13: idle STA's stale weak signal ignored; steered once it sends again")


LB_STAS = ["aa:bb:cc:dd:ee:%02x" % (0x19 + i) for i in range(3)]  # S14: idle STAs on a busy AP2


def scenario_lb_feedback(world, procs, logs, socks, tmp, ap1, ap2):
    """S14: AP2 is 90 % busy and moving its idle STAs does not lower that
    (the mock's utilisation is fixed, like interference). After
    lb_max_futile (2) such moves, AP2 pauses load balancing instead of
    pushing out every idle STA."""
    mark(logs, "S14 load balancing stops when offloading does not help")
    stas = [Sta(m, -58, {B1: (115, 36, -60)}, rrm={0}) for m in LB_STAS]
    with world.lock:
        ap1.util = 30
        for s in stas:
            ap2.add_sta(s)
        ap2.util = 230  # ~90 %, and it stays there
    wait_for(lambda: "load balancing paused" in open(logs[1].name).read().split("=== S14")[-1], 30,
             "AP2 to pause load balancing")
    log2 = open(logs[1].name).read().split("=== S14")[-1]
    moved = [m for m in LB_STAS if m in ap1.stas]
    assert log2.count("did not lower utilisation") == 2, log2.count("did not lower utilisation")
    assert len(moved) == 2, moved
    time.sleep(4.0)  # paused: the last idle STA stays
    assert sum(1 for m in LB_STAS if m in ap1.stas) == 2, "offloading continued after the pause"
    with world.lock:
        ap2.util = 25
        for m in LB_STAS:
            for b in (ap1, ap2):
                if m in b.stas:
                    b.remove_sta(m)
    print("PASS 14: load balancing paused after 2 offloads that did not lower utilisation "
          "(last idle STA kept)")


def scenario_many_bss(world, procs, logs, tmp, base):
    """S15: an AP with 17 BSSes (32-character SSIDs: the largest HELLO and
    BSS_STATUS frames). It starts, warns about the 17th, manages 16, and its
    peer receives all 16 with their load."""
    ssid = "S" * 32
    ports = [base + 40, base + 41]
    hdirs = [os.path.join(tmp, "mbhapd%d" % i) for i in (0, 1)]
    for h in hdirs:
        os.makedirs(h, exist_ok=True)
    chans = [(5180 + 20 * (k % 8), 36 + 4 * (k % 8)) if k < 8 else (2412 + 5 * (k % 8), 1 + (k % 8))
             for k in range(17)]
    lines = []
    for k in range(17):
        world.add_bss(hdirs[0], "mb0-wl%d" % k, "02:00:00:00:60:%02x" % k, ssid, chans[k][0], chans[k][1], util=20)
        if k > 0:
            lines.append("bss mb0-wl%d mdid=a1b2" % k)
    world.add_bss(hdirs[1], "mb1-wl0", "02:00:00:00:61:00", ssid, 5745, 149, util=20)
    socks, mlogs = [], []
    for i in (0, 1):
        cfg, sock = os.path.join(tmp, "mb%d.conf" % i), os.path.join(tmp, "mbctrl%d" % i)
        extra = "\n".join(lines) + "\n" if i == 0 else ""
        write_cfg(cfg, "02:00:00:00:00:%02x" % (0x60 + i), "mb%d" % i, hdirs[i], sock, ports[i],
                  [ports[1 - i]], "many-bss-key", extra=extra)
        path = os.path.join(tmp, "mb%d.log" % i)
        log = open(path, "a")
        mlogs.append(log)
        socks.append(sock)
        procs.append(subprocess.Popen(DONGHOA + ["-c", cfg, "-d"], stderr=log))
    mark(logs + mlogs, "S15 an AP with 17 BSSes: 16 managed, all 16 reach the peer")
    bsslines = lambda out: [l for l in out.splitlines() if l.startswith("  bss 02:00:00:00:60:")]
    wait_for(lambda: len([l for l in bsslines(cli(socks[1], "PEERS")) if "util=" in l]) == 16, 15,
             "the peer to see 16 BSSes with load")
    up = [l for l in cli(socks[0], "STATUS").splitlines() if l.startswith("mb0-wl") and l.endswith(" up")]
    mlogs[0].flush()
    warned = "1 bss line(s) beyond the limit of 16 ignored (first: mb0-wl16)" in open(mlogs[0].name).read()
    for p in procs[-2:]:
        p.send_signal(signal.SIGTERM)
    for p in procs[-2:]:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    assert len(up) == 16, up
    assert warned, "warning about the 17th bss line"
    print("PASS 15: AP with 17 BSSes starts, manages 16 (warning), peer receives all 16 with load")


SCALE_APS = 12
STA17_MAC = "aa:bb:cc:dd:ee:17"  # S12: hears only the BSS of the last peer in the pool order


def scenario_scale(world, procs, logs, tmp, base):
    """S12: 12 APs with 2 BSSes each, a separate ESS and key. More BSSes
    qualify (23) than one steer measures (16). The STA hears only a BSS of
    the peer the source visits last, which the first pool cannot hold: its
    802.11k report of that BSS ranks it into the next pool."""
    ports = [base + 20 + i for i in range(SCALE_APS)]
    socks, scale_logs, bss = [], [], []
    for i in range(SCALE_APS):
        name, hdir = "sc%d" % i, os.path.join(tmp, "schapd%d" % i)
        os.makedirs(hdir, exist_ok=True)
        b5, b2 = "02:00:00:00:%02x:00" % (0x40 + i), "02:00:00:00:%02x:01" % (0x40 + i)
        world.add_bss(hdir, name + "-wl0", b5, "scale", 5180, 36, util=20)
        world.add_bss(hdir, name + "-wl1", b2, "scale", 2437, 6, util=20)
        bss.append((b5, b2))
        cfg, sock = os.path.join(tmp, name + ".conf"), os.path.join(tmp, "sctrl%d" % i)
        write_cfg(cfg, "02:00:00:00:00:%02x" % (0x40 + i), name, hdir, sock, ports[i],
                  [q for q in ports if q != ports[i]], "scale-mesh-key", extra="bss %s-wl1 mdid=a1b2\n" % name)
        path = os.path.join(tmp, name + ".log")
        log = open(path, "a")
        scale_logs.append(log)
        socks.append(sock)
        procs.append(subprocess.Popen(DONGHOA + ["-c", cfg, "-d"], stderr=log))
    mark(logs + scale_logs, "S12 scale: 12 APs, more BSSes than one steer can measure")
    npeers = lambda sk: sum(1 for l in cli(sk, "PEERS").splitlines() if l.startswith("peer "))
    wait_for(lambda: all(npeers(sk) == SCALE_APS - 1 for sk in socks), 15, "all 12 APs to see 11 peers")
    order = [l.split()[1] for l in cli(socks[0], "PEERS").splitlines() if l.startswith("peer ")]
    last = int(order[-1].split(":")[-1], 16) - 0x40
    target = bss[last][0]
    with world.lock:
        src = world.bss_by_bssid[bss[0][0]]
        sta = Sta(STA17_MAC, -82, {target: (115, 36, -55)}, rrm={0})
        src.add_sta(sta)
    wait_for(lambda: STA17_MAC in world.bss_by_bssid[target].stas, 25,
             "STA17 to be steered to the last peer's BSS %s" % target)
    for log in scale_logs:
        log.flush()
    log0 = open(scale_logs[0].name).read()
    assert "more BSSes than the 16 the pool holds" in log0, "the pool overflowed"
    starts = log0.count(STA17_MAC + " start: reason rssi")
    btm_to = [t[2] for t in world.btm_log if t[1] == STA17_MAC]
    assert btm_to and btm_to[-1] == target, btm_to
    for p in procs[-SCALE_APS:]:
        p.send_signal(signal.SIGTERM)
    for p in procs[-SCALE_APS:]:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    print("PASS 12: 12 APs / 23 candidate BSSes: STA steered to the one BSS it hears, on the last "
          "peer (steer attempt %d)" % starts)


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
        world.add_bss(h1, "ap1-mld_link0", BM0, "home", 5220, 44, netdev="ap1-mld", mld=BMLD, link_id=0)
        apm1 = world.add_bss(h1, "ap1-mld_link1", BM1, "home", 2462, 11, netdev="ap1-mld", mld=BMLD,
                             link_id=1)
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
                mon = ("bss ap1-wl1 mdid=a1b2\nbss ap1-wl2 mdid=a1b2\n"
                       "bss ap1-mld_link0 mdid=a1b2\nbss ap1-mld_link1 mdid=a1b2\n"
                       f"sta_rssi_sim {os.path.join(tmp, 'rssi_ap1')}\n")
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
            print("SKIP 7, 8, 9: band steering and MLO scenarios assume score_model 0 (20 MHz mock BSSes)")
            scenario_low_power(world, procs, logs, socks, tmp, ap1, ap2)
            scenario_driver_rssi(world, procs, logs, socks, tmp, ap1, ap2)
            scenario_idle_signal(world, procs, logs, socks, tmp, ap1, ap2)
            scenario_lb_feedback(world, procs, logs, socks, tmp, ap1, ap2)
            scenario_many_bss(world, procs, logs, tmp, base)
            scenario_scale(world, procs, logs, tmp, base)
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

        mark(logs, "S9 MLO: MLD STA on both links of AP1's AP MLD")
        apm0 = world.bss_by_bssid[BM0]
        # Both own links look better than B1 in beacon reports: only the
        # own-AP-MLD rule keeps the roam off them, whichever link is the source.
        sta10 = Sta(STA10_MAC, -40, {B1: (115, 36, -50), BM0: (115, 44, -35), BM1: (81, 11, -30)},
                    mld_links={0: "aa:bb:cc:dd:ee:20", 1: "aa:bb:cc:dd:ee:21"},
                    link_signal={BM0: -45, BM1: -40})
        n_btm = len(world.btm_log)
        with world.lock:
            apm0.add_sta(sta10)        # association link: event
            apm1.stas[STA10_MAC] = sta10  # partner link: listed by STA-FIRST/NEXT
        sta_line = lambda: next((l for l in cli(socks[0], "STAS").splitlines()
                                 if l.startswith("sta " + STA10_MAC)), "")
        wait_for(lambda: "mld links=" in sta_line(), 3, "MLD STA with its links in STAS")
        # Strong on the 2.4 GHz link (-40): a non-MLD STA would be band-steered
        time.sleep(3.0)
        line = sta_line()
        assert ("bss=ap1-mld_link1 " in line and "ap1-mld_link0:0:-45" in line
                and "ap1-mld_link1:1:-40" in line and "rssi=-40 " in line), line
        assert not any(t[1] == STA10_MAC for t in world.btm_log[n_btm:]), "MLD STA must not be band-steered"
        assert "steer #" not in "".join(l for l in open(logs[0].name).read().split("=== S9")[-1].splitlines(True)
                                         if STA10_MAC in l and "start" in l), "no steer may start"
        st = cli(socks[0], "STATUS")
        assert "mld=" + BMLD + " link=0" in st and "mld=" + BMLD + " link=1" in st, st
        # One link weak, the other good: no roam
        sta10.link_signal = {BM0: -45, BM1: -85}
        time.sleep(3.0)
        assert not any(t[1] == STA10_MAC for t in world.btm_log[n_btm:]), "no roam while a link is good"
        assert "bss=ap1-mld_link0 " in sta_line(), sta_line()
        # Every link weak: roam, to B1 (5 GHz), not to the AP MLD's own 5 GHz link
        sta10.link_signal = {BM0: -86, BM1: -85}
        wait_for(lambda: any(t[1] == STA10_MAC for t in world.btm_log[n_btm:]), 10, "roam of the MLD STA")
        btm = [t for t in world.btm_log[n_btm:] if t[1] == STA10_MAC][0]
        assert btm[2] == B1 and btm[2] not in (BM0, BM1), btm
        wait_for(lambda: "finished: success" in "".join(
            l for l in open(logs[0].name).read().split("=== S9")[-1].splitlines(True) if STA10_MAC in l),
            4, "MLD STA roam recorded as success")
        print("PASS 9: MLO: one entry per MLD STA, no band steer onto its own link, roam only when all links are weak")
        scenario_low_power(world, procs, logs, socks, tmp, ap1, ap2)
        scenario_driver_rssi(world, procs, logs, socks, tmp, ap1, ap2)
        scenario_idle_signal(world, procs, logs, socks, tmp, ap1, ap2)
        scenario_lb_feedback(world, procs, logs, socks, tmp, ap1, ap2)
        scenario_many_bss(world, procs, logs, tmp, base)
        scenario_scale(world, procs, logs, tmp, base)
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
