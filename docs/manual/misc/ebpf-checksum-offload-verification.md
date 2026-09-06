# eBPF checksum/offload verification

This is the real-hardware verification procedure for item 13 of the eBPF
inbound reliability work: whether the packets this inbound's TC programs
rewrite in place (bypass_rule_set CIDR matching, `shared.data_plane:
packet_rewrite`, and `fakeip_icmp: reply`'s incremental ICMP checksum update)
remain correct once a real NIC's checksum offload, GRO, GSO, or TSO is
involved. Every other test in this codebase runs against veth pairs in
network namespaces, which have no hardware offload path at all — a software
loopback always computes checksums honestly regardless of what NIC feature
flags claim, so those tests cannot catch a rewrite that only an offloading
NIC's firmware or driver would mishandle.

**This procedure has not been run.** No environment with two real Linux
hosts joined by a real NIC was available while this round of work was done.
It ships as a documented, ready-to-run script and procedure for whoever has
that hardware, not as a claim that hardware behavior has been checked.

## Why a real NIC, specifically

A veth pair's "hardware" checksum offload flags are advisory only — the
kernel's software networking stack always computes a correct checksum
regardless of what `ethtool -k veth0` reports, because there is no real
device firmware in the path to skip that work. A cloud VM's virtio-net
interface behaves the same way for the same reason: virtio-net's "hardware"
checksum offload is itself implemented in the hypervisor's software network
stack. Only a physical NIC (or a SR-IOV/passthrough virtual function backed
by one) with a real onboard checksum/segmentation engine exercises the code
path this procedure is checking: an eBPF program changing header bytes
in a packet the NIC's own silicon or firmware, not the kernel, will finish
checksumming before it leaves the machine.

## Required environment

- Two real Linux hosts connected by a real NIC on each end — a physical
  Ethernet link, or a datacenter NIC configured for SR-IOV passthrough into
  a VM. Confirm with `ethtool -i <iface>` that the driver is a real hardware
  driver (`ixgbe`, `i40e`, `mlx5_core`, `r8169`, `igc`, ... — not `veth`,
  `virtio_net`, or `vmxnet3`).
- Root on both hosts, and non-interactive (key-based) SSH from the host under
  test to the peer.
- `ethtool`, `tcpdump`, and `nc` (netcat) on both hosts.
- sing-box built with the eBPF inbound already running on the host under
  test, attached to the NIC named `$LOCAL_IFACE`, with a configuration that
  exercises the paths this procedure checks:
  - `fakeip_icmp: reply` enabled, with a FakeIP prefix that matches
    `$FAKEIP_PREFIX` below.
  - `shared.data_plane: packet_rewrite` enabled if `$REMOTE_PORT_TCP` /
    `$REMOTE_PORT_UDP` are set (to exercise the NAT/flow-rewrite path).
  - Route the peer host through this inbound so `bypass_rule_set` (if
    configured) has a real matched flow to evaluate.

## Running it

```sh
sudo LOCAL_IFACE=eth0 \
    REMOTE_HOST=192.0.2.10 \
    REMOTE_SSH_USER=root \
    FAKEIP_PREFIX=198.18.0.0/15 \
    REMOTE_FAKEIP_TARGET=198.18.0.1 \
    REMOTE_IPV6=fdfe:dcba:9876::1 \
    REMOTE_PORT_TCP=15000 \
    REMOTE_PORT_UDP=15001 \
    common/ebpf/testing/checksum_offload_verify.sh
```

Only `LOCAL_IFACE`, `REMOTE_HOST`, `FAKEIP_PREFIX`, and
`REMOTE_FAKEIP_TARGET` are required; the rest narrow or widen what gets
checked (see the script's own header comment for the full list and
defaults). The script:

1. Reads `$LOCAL_IFACE`'s current offload feature flags via `ethtool -k` and
   records them, to restore exactly on exit (including on Ctrl-C).
2. Runs four offload combinations by default — all relevant features on, all
   off, TX checksumming off alone, and TSO/GSO off alone. This is a
   deliberately small slice of the full 2^6 power set: "all on" is the
   default production case, "all off" isolates whether the eBPF rewrite
   itself is correct independent of any offload, and the two single-feature
   cases isolate the specific offload most likely to interact badly with an
   in-place header rewrite (TX checksum insertion assumes the checksum field
   holds what software would have computed; segmentation offload assumes a
   single logical packet the driver replicates headers for). Extend
   `OFFLOAD_MATRIX` in the script if a specific NIC or driver needs finer
   coverage — for example if `ethtool -k` reports offload features beyond
   the six the script already recognizes.
3. For each combination, runs and captures (via `tcpdump`, on both hosts):
   - A control transfer over the plain SSH connection to `$REMOTE_HOST`
     (exercises the interface and its offload settings without going
     through any eBPF rewrite at all — a failure here means the NIC/driver
     combination itself is the problem, not this inbound).
   - A FakeIP ICMP echo to `$REMOTE_FAKEIP_TARGET` (IPv4), and to
     `$REMOTE_IPV6` if set (IPv6).
   - A TCP transfer through `$REMOTE_PORT_TCP` if set, and a UDP transfer
     through `$REMOTE_PORT_UDP` if set (both exercise
     `shared.data_plane: packet_rewrite`'s address/port rewrite).
4. Records PASS/FAIL to `$OUT_DIR/report.tsv` based on what the **receiving**
   host's kernel actually accepted — packet loss for ICMP, byte count for
   the transfers — never based on `tcpdump`'s own checksum annotation on the
   sending side. A capture taken before the NIC's own checksum engine runs
   routinely says "incorrect" even for packets a real receiver accepts
   without issue; that is a property of capturing before TX offload, not a
   real defect, and treating it as one would make every run fail regardless
   of whether the eBPF rewrite is actually correct. This is why the receiving
   host's own accept/drop and byte-count behavior is authoritative and
   `tcpdump`'s inline checksum verdict is not used as a pass/fail signal at
   all — only as raw evidence to attach to a report when something else
   already failed.

## Reading a failure

- **Control transfer fails on some combination**: the NIC/driver itself
  cannot run with that offload combination on this hardware — not an eBPF
  issue. Fix the driver/firmware combination (or exclude that combination on
  this hardware) before drawing any conclusion about the eBPF rewrite paths.
- **Control transfer passes but FakeIP ICMP or the rewrite transfers fail on
  the same combination**: this is the actual finding this procedure exists
  to catch — an eBPF-rewritten packet is wire-incorrect specifically under
  that offload combination. Attach both hosts' `.pcap` files from
  `$OUT_DIR` to the report; the receiving host's capture (not the sending
  host's) is the one to inspect first, since it is the one downstream of any
  real offload computation.
- **Everything passes with all offload features on and off**: the code
  checked in this round does not depend on this NIC's offload behavior in a
  way this procedure can detect. Record the NIC model, driver, and firmware
  version alongside the PASS result — a different NIC/driver is still an
  open question, not something this one clean run answers for every device.

## What this does not cover

- Android hardware. This procedure is written for the two-Linux-host case;
  Android's networking stack, driver model, and available tooling (`nc`,
  `tcpdump` availability, `ethtool` support) differ enough that it needs its
  own pass on a real device, not an adaptation of this script.
- TCX-specific offload interaction. The script does not select attachment
  mechanism (TCX vs `clsact`) — that is controlled by the sing-box
  configuration already running on the host under test, not by this script.
  Run the procedure once per mechanism if both need checking on the same
  hardware.
- Any offload feature `ethtool -k` does not report as one of the six the
  script recognizes (`rx-checksumming`, `tx-checksumming`,
  `generic-segmentation-offload`, `tcp-segmentation-offload`,
  `generic-receive-offload`, `tx-udp-segmentation`). Extend
  `RELEVANT_FEATURES` and `OFFLOAD_MATRIX` in the script for a NIC that
  exposes something else relevant (for example a vendor-specific
  `rx-udp-gro-forwarding` or `tx-checksum-ip-generic` flag).
