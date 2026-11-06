# SPDX-License-Identifier: MIT
"""Minimal hostapd control-interface emulator for integration tests.

Implements only the commands/events donghoa uses. One World holds every mock
BSS and models STAs moving between them when they accept a BTM request.
"""
import os
import selectors
import socket
import threading
import time


class Sta:
    def __init__(self, mac, signal, view, btm_accept=True, tput_bytes=0, rrm=True,
                 op_classes=None, akm="00-0f-ac-4", mld_links=None, link_signal=None,
                 traffic=None, phy_caps=None):
        self.mac = mac
        # Extra flags=[...] entries, e.g. ["VHT", "HE"]: a STA this capable
        # is never low-power regardless of its traffic shape.
        self.phy_caps = list(phy_caps or [])
        # Per-poll traffic: traffic(n) -> (uplink bytes, downlink bytes) for
        # the n-th listing; None: tput_bytes both ways.
        self.traffic = traffic
        self.polls = 0
        # Wi-Fi 7 MLO: link id -> link address (peer_addr[]) for an MLD STA,
        # printed only by AP MLD links; per-link signal by BSSID.
        self.mld_links = dict(mld_links or {})
        self.link_signal = dict(link_signal or {})
        self.akm = akm  # AKMSuiteSelector of the association (FT-PSK default)
        # Supported Operating Classes element body as hex (current class
        # first), printed as supp_op_classes=; None: element not sent.
        self.op_classes = op_classes
        # Beacon report modes advertised in RM Enabled Capabilities
        # (0 passive, 1 active, 2 table). True: all, False: none. Like
        # hostapd, REQ_BEACON for a mode not advertised fails.
        self.rrm_modes = {0, 1, 2} if rrm is True else set(rrm or ())
        self.signal = signal
        # bssid -> (op_class, channel, rssi dBm) as seen by this STA
        self.view = dict(view)
        self.btm_accept = btm_accept
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.tput_bytes = tput_bytes  # added per STA poll


class MockBss:
    def __init__(self, world, ctrl_dir, ifname, bssid, ssid, freq, channel, util=None,
                 netdev=None, mld=None, link_id=None):
        self.world = world
        self.ifname = ifname  # control socket name ("<netdev>_link<id>" for an AP MLD link)
        self.netdev = netdev or ifname
        self.mld = mld        # AP MLD address, None for a plain BSS
        self.link_id = link_id
        self.bssid = bssid
        self.ssid = ssid
        self.freq = freq
        self.channel = channel
        self.util = util
        self.stas = {}
        self.clients = set()
        self.neighbors = {}
        self.cmd_log = []
        self.token = 0
        os.makedirs(ctrl_dir, exist_ok=True)
        self.path = os.path.join(ctrl_dir, ifname)
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.path)
        self.sock.setblocking(False)

    # -- events --
    def event(self, text):
        for c in list(self.clients):
            try:
                self.sock.sendto(("<3>" + text).encode(), c)
            except OSError:
                self.clients.discard(c)

    def add_sta(self, sta):
        self.stas[sta.mac] = sta
        self.event("AP-STA-CONNECTED " + sta.mac)

    def remove_sta(self, mac):
        if self.stas.pop(mac, None):
            self.event("AP-STA-DISCONNECTED " + mac)

    # -- commands --
    def status(self):
        lines = [
            "state=ENABLED", "freq=%d" % self.freq, "channel=%d" % self.channel,
            "ieee80211n=1", "ieee80211ac=%d" % (self.freq > 5000), "ieee80211ax=0",
            "max_txpower=20", "bss[0]=" + self.netdev, "bssid[0]=" + self.bssid,
            "ssid[0]=" + self.ssid, "num_sta[0]=%d" % len(self.stas),
        ]
        if self.mld:
            lines += ["ieee80211be=1", "mld_addr[0]=" + self.mld, "mld_id[0]=0",
                      "mld_link_id[0]=%d" % self.link_id]
        if self.util is not None:
            lines.append("chan_util_avg=%d" % self.util)
        return "\n".join(lines) + "\n"

    def sta_text(self, sta):
        if sta.traffic:
            up, down = sta.traffic(sta.polls)
            sta.polls += 1
            sta.rx_bytes += up    # hostapd counts from the AP: rx = uplink
            sta.tx_bytes += down
        else:
            sta.rx_bytes += sta.tput_bytes
            sta.tx_bytes += sta.tput_bytes
        flags = "[AUTH][ASSOC][AUTHORIZED][WMM][HT]" + "".join("[%s]" % f for f in sta.phy_caps)
        text = (
            "%s\nflags=%s\nrx_bytes=%d\ntx_bytes=%d\n"
            "inactive_msec=100\nsignal=%d\nrx_rate_info=1200\ntx_rate_info=1200\n"
            "connected_time=10\next_capab=0000080000000040\nAKMSuiteSelector=%s\n"
            % (sta.mac, flags, sta.rx_bytes, sta.tx_bytes, sta.link_signal.get(self.bssid, sta.signal), sta.akm)
        )
        if self.mld and sta.mld_links:
            for lid, addr in sorted(sta.mld_links.items()):
                text += "peer_addr[%d]=%s\n" % (lid, addr)
            text += "max_simul_links=1\n"
        if sta.op_classes:
            text += "supp_op_classes=%s\n" % sta.op_classes
        return text

    def handle(self, cmd, addr):
        self.cmd_log.append(cmd)
        w = cmd.split()
        op = w[0] if w else ""
        if op == "ATTACH":
            self.clients.add(addr)
            return "OK\n"
        if op == "DETACH":
            self.clients.discard(addr)
            return "OK\n"
        if op == "STATUS":
            return self.status()
        if op == "GET_CONFIG":
            return "bssid=%s\nssid=%s\nwpa=2\nkey_mgmt=WPA-PSK FT-PSK\n" % (self.bssid, self.ssid)
        if op == "STA-FIRST":
            macs = sorted(self.stas)
            return self.sta_text(self.stas[macs[0]]) if macs else ""
        if op == "STA-NEXT":
            macs = sorted(self.stas)
            nxt = [m for m in macs if m > w[1]]
            return self.sta_text(self.stas[nxt[0]]) if nxt else ""
        if op == "STA":
            return self.sta_text(self.stas[w[1]]) if w[1] in self.stas else "FAIL\n"
        if op == "SET_NEIGHBOR":
            self.neighbors[w[1]] = cmd
            return "OK\n"
        if op == "REMOVE_NEIGHBOR":
            self.neighbors.pop(w[1], None)
            return "OK\n"
        if op == "REQ_BEACON":
            return self.req_beacon(w)
        if op == "BSS_TM_REQ":
            return self.bss_tm_req(w)
        return "UNKNOWN COMMAND\n"

    def req_beacon(self, w):
        sta = self.stas.get(w[1])
        req = bytes.fromhex(w[-1])
        if not sta or len(req) < 7 or req[6] not in sta.rrm_modes:
            return "FAIL\n"
        chans = {req[1]}
        if req[1] == 255:
            # Channel 255: the channels come from AP Channel Report
            # subelements (ID 51: op class, channel list) after the fixed
            # 13 bytes.
            chans, i = set(), 13
            while i + 2 <= len(req):
                sid, ln = req[i], req[i + 1]
                if sid == 51:
                    chans.update(req[i + 3:i + 2 + ln])
                i += 2 + ln
        self.token += 1
        tok = self.token

        def reply():
            for bssid, (op, ch, rssi) in sta.view.items():
                if ch not in chans:
                    continue
                rcpi = max(0, min(220, 2 * (rssi + 110)))
                body = bytes([op, ch]) + bytes(8) + (50).to_bytes(2, "little")
                body += bytes([0, rcpi, 0]) + bytes.fromhex(bssid.replace(":", ""))
                body += bytes(5)
                self.event("BEACON-RESP-RX %s %d 00 %s" % (sta.mac, tok, body.hex()))

        self.world.later(0.05, reply)
        return "%d\n" % tok

    def bss_tm_req(self, w):
        mac = w[1]
        sta = self.stas.get(mac)
        if not sta:
            return "FAIL\n"
        nbr = [x for x in w if x.startswith("neighbor=")]
        target = nbr[0].split("=", 1)[1].split(",")[0] if nbr else None
        self.world.btm_log.append((self.bssid, mac, target, " ".join(w)))

        def respond():
            if not sta.btm_accept or target not in self.world.bss_by_bssid:
                self.event("BSS-TM-RESP %s dialog_token=1 status_code=1 "
                           "bss_termination_delay=0" % mac)
                return
            self.event("BSS-TM-RESP %s dialog_token=1 status_code=0 bss_termination_delay=0 "
                       "target_bssid=%s" % (mac, target))
            self.world.later(0.1, lambda: self.world.move(mac, self.bssid, target))

        self.world.later(0.05, respond)
        return "OK\n"


class World:
    def __init__(self):
        self.sel = selectors.DefaultSelector()
        self.bss_by_bssid = {}
        self.btm_log = []
        self.timers = []
        self.lock = threading.RLock()
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)

    def add_bss(self, *a, **kw):
        b = MockBss(self, *a, **kw)
        self.bss_by_bssid[b.bssid] = b
        self.sel.register(b.sock, selectors.EVENT_READ, b)
        return b

    def later(self, delay, fn):
        with self.lock:
            self.timers.append((time.time() + delay, fn))

    def move(self, mac, src_bssid, dst_bssid):
        """STA roams: connect at target first (as with FT), then leave source."""
        with self.lock:
            src = self.bss_by_bssid[src_bssid]
            dst = self.bss_by_bssid[dst_bssid]
            sta = src.stas.get(mac)
            if not sta:
                return
            # Swap perspective: what it saw as target becomes current signal.
            sig = sta.view.get(dst_bssid, (0, 0, sta.signal))[2]
            sta.view[src_bssid] = (0, src.channel, sta.signal)
            sta.signal = sig
            sta.link_signal = {}
            dst.add_sta(sta)
            # An MLD STA leaves every link of the source AP MLD.
            for b in self.bss_by_bssid.values():
                if b is not dst and mac in b.stas:
                    b.remove_sta(mac)

    def start(self):
        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join(timeout=2)
        for b in self.bss_by_bssid.values():
            b.sock.close()
            if os.path.exists(b.path):
                os.unlink(b.path)

    def run(self):
        while self.running:
            for key, _ in self.sel.select(timeout=0.02):
                b = key.data
                try:
                    data, addr = b.sock.recvfrom(4096)
                except BlockingIOError:
                    continue
                with self.lock:
                    reply = b.handle(data.decode(errors="replace").strip(), addr)
                try:
                    b.sock.sendto(reply.encode(), addr)
                except OSError:
                    pass
            now = time.time()
            with self.lock:
                due = [t for t in self.timers if t[0] <= now]
                self.timers = [t for t in self.timers if t[0] > now]
            for _, fn in due:
                with self.lock:
                    fn()
