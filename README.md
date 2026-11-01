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
- **Air monitor:** a STA without 802.11k, or too busy to answer a Beacon
  Request, is measured instead by the radiotap monitor interfaces of the
  candidate APs (`air_monitor`), from the frames it sends.

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
donghoa -c /etc/donghoa.conf               # needs CAP_NET_RAW; -d all debug, -s syslog
donghoa_cli /var/run/donghoa.sock PEERS    # STATUS | PEERS | STAS | STEERS | PING
donghoa_cli /var/run/donghoa.sock LOG debug steer msg   # debug two modules, no restart
donghoa_cli /var/run/donghoa.sock STEER aa:bb:cc:dd:ee:ff [target-bssid]
```

**Debugging.** Log lines name their module, for example `steer:` or `msg:`.
`LOG` shows each module's level; `LOG debug <module>...` raises it at run time
and `LOG info` resets all. With `msg` at debug, every ARCP frame is traced:
`tx STEER_REQ #19 02:00:00:00:00:02 via eth1 [ack-req] [auth]: STEER_REQ AUTH`.
Modules: main l2 msg peer hapd local steer policy amon survey ctrl config.

hostapd needs `bss_transition=1`, `rrm_neighbor_report=1`,
`rrm_beacon_report=1` and an FT configuration whose `mobility_domain` matches
the `mdid=` of each `bss` line. See `docs/ARCHITECTURE.md`.

## Documentation

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
