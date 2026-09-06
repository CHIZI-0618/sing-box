# eBPF 校验和/卸载验证

这是 eBPF 入站可靠性工作第 13 项的实机验证流程：本入站的 TC 程序原地改写的报文
（bypass_rule_set CIDR 匹配、`shared.data_plane: packet_rewrite`，以及
`fakeip_icmp: reply` 的增量 ICMP 校验和更新）在涉及真实网卡的校验和卸载、GRO、
GSO 或 TSO 时是否仍然正确。本代码库中的其他测试都运行在 network namespace 里的
veth pair 上，而 veth 完全没有硬件卸载路径——软件回环无论网卡特性标志如何声明，
都会如实计算校验和，因此这些测试无法发现只有真实卸载网卡的固件或驱动才会出错
的改写。

**这套流程尚未实际执行过。** 在完成本轮工作期间，没有可用的、由真实网卡连接
两台真实 Linux 主机的环境。它以脚本加文档的形式交付，供拥有该硬件的人直接
运行，而不是声称硬件行为已经验证过。

## 为什么必须是真实网卡

veth pair 的"硬件"校验和卸载标志只是摆设——内核的软件网络栈总会如实计算正确
的校验和，无论 `ethtool -k veth0` 报告什么，因为链路上根本没有真实的设备固件
会跳过这项工作。云主机的 virtio-net 接口出于同样的原因表现相同：virtio-net 的
"硬件"校验和卸载本身就是由 hypervisor 的软件网络栈实现的。只有物理网卡（或
SR-IOV/直通到虚拟机、背后是物理网卡的虚拟功能）才具备本流程要检查的真实
片上校验和/分段引擎：eBPF 程序改写报文头部字节后，最终完成校验和计算的是网卡
自身的硬件或固件，而不是内核——这正是本流程要检验的代码路径。

## 所需环境

- 两台由真实网卡连接的 Linux 主机——物理以太网链路，或配置为 SR-IOV 直通进
  虚拟机的数据中心网卡。用 `ethtool -i <iface>` 确认驱动是真实硬件驱动
  （`ixgbe`、`i40e`、`mlx5_core`、`r8169`、`igc` 等——不是 `veth`、
  `virtio_net` 或 `vmxnet3`）。
- 两台主机都有 root 权限，且被测主机能以非交互方式（密钥认证）SSH 到对端。
- 两台主机都安装 `ethtool`、`tcpdump` 和 `nc`（netcat）。
- 被测主机已经运行着接到 `$LOCAL_IFACE` 网卡的 sing-box eBPF 入站，其配置
  覆盖本流程要检查的路径：
  - 启用 `fakeip_icmp: reply`，其 FakeIP 前缀与下面的 `$FAKEIP_PREFIX` 一致。
  - 如果设置了 `$REMOTE_PORT_TCP` / `$REMOTE_PORT_UDP`，需启用
    `shared.data_plane: packet_rewrite`（用于覆盖 NAT/流改写路径）。
  - 让对端主机的流量经过本入站路由，这样若配置了 `bypass_rule_set` 就有
    真实的匹配流量可供评估。

## 运行方式

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

只有 `LOCAL_IFACE`、`REMOTE_HOST`、`FAKEIP_PREFIX`、`REMOTE_FAKEIP_TARGET`
是必需的；其余变量用于收窄或扩大检查范围（完整列表及默认值见脚本自身的头部
注释）。该脚本会：

1. 通过 `ethtool -k` 读取并记录 `$LOCAL_IFACE` 当前的卸载特性标志，以便在
   退出时（包括 Ctrl-C 中断时）精确恢复。
2. 默认运行四种卸载组合——全部相关特性打开、全部关闭、仅关闭 TX 校验和、
   仅关闭 TSO/GSO。这是完整 2^6 幂集中特意精简出的一小部分："全部打开"是
   默认生产场景，"全部关闭"用于隔离验证 eBPF 改写本身是否正确（与任何卸载
   无关），另外两个单特性场景则分别隔离出最可能与原地报文头改写产生不良
   交互的两种卸载（TX 校验和插入会假设校验和字段中已经是软件本应计算出的
   值；分段卸载则假设这是驱动要为其复制报文头的单一逻辑报文）。如果某块
   网卡或驱动需要更细的覆盖——例如 `ethtool -k` 报告了脚本尚未识别的其他
   六种特性之外的卸载特性——可在脚本中扩展 `OFFLOAD_MATRIX`。
3. 针对每种组合，运行并（在两台主机上通过 `tcpdump`）抓包：
   - 一次经普通 SSH 连接到 `$REMOTE_HOST` 的对照传输（完全不经过任何 eBPF
     改写，只检验该网卡及其卸载设置本身——如果这一步失败，说明问题出在
     网卡/驱动组合本身，与本入站无关）。
   - 一次发往 `$REMOTE_FAKEIP_TARGET` 的 FakeIP ICMP echo（IPv4），以及
     （若设置了 `$REMOTE_IPV6`）发往该地址的 IPv6 echo。
   - 若设置了 `$REMOTE_PORT_TCP`，则通过它做一次 TCP 传输；若设置了
     `$REMOTE_PORT_UDP`，则通过它做一次 UDP 传输（两者都用于覆盖
     `shared.data_plane: packet_rewrite` 的地址/端口改写路径）。
4. 将 PASS/FAIL 记录到 `$OUT_DIR/report.tsv`，判定依据是**接收端**主机内核
   实际接受了什么——ICMP 看丢包率，传输看字节数——而不是发送端 `tcpdump` 自身
   给出的校验和判定。在网卡自身的校验和引擎完成工作之前抓到的包，即使
   真实的接收方完全正常接受，也常常被标为"incorrect"；这是"在 TX 卸载生效
   之前抓包"这件事本身的特性，并不是真实缺陷——如果把它当作缺陷来判定，
   无论 eBPF 改写是否正确，每次运行都会被判为失败。这正是为什么本流程以
   接收端主机自身的接受/丢弃行为和字节数为准，而完全不把 `tcpdump` 的内联
   校验和判定作为通过/失败信号——它只在其他判定已经失败时，作为附加在
   报告里的原始证据使用。

## 如何解读失败

- **对照传输在某种组合下失败**：说明这块硬件上的网卡/驱动组合本身无法在该
  卸载组合下正常工作——与 eBPF 无关。应先修复该网卡/驱动固件组合（或在这块
  硬件上直接排除该组合），再对 eBPF 改写路径下结论。
- **对照传输通过，但同一组合下 FakeIP ICMP 或改写传输失败**：这正是本流程
  要捕捉的真实发现——某个 eBPF 改写后的报文，在该卸载组合下在线路上确实是
  错误的。请将 `$OUT_DIR` 下两台主机的 `.pcap` 文件一并附到报告中；应优先
  查看接收端主机的抓包（而不是发送端的），因为它才是真正经过了网卡实际
  校验和计算之后的那一份。
- **打开和关闭所有卸载特性都全部通过**：说明本轮所检查的代码在这块网卡上，
  并不以这套流程能检测到的方式依赖其卸载行为。请把网卡型号、驱动和固件
  版本随 PASS 结果一并记录下来——换一块网卡/驱动仍然是一个待验证的问题，
  这一次干净的运行结果并不能替所有设备回答它。

## 本流程未覆盖的范围

- Android 硬件。本流程是按两台 Linux 主机的场景编写的；Android 的网络栈、
  驱动模型和可用工具（`nc`、`tcpdump` 是否可用、`ethtool` 支持程度）差异
  大到需要在真实设备上单独走一遍，而不是直接照搬本脚本。
- TCX 相关的卸载交互。脚本本身不选择挂载机制（TCX 还是 `clsact`）——这由
  被测主机上已经在运行的 sing-box 配置决定，而不是由本脚本决定。如果同一
  硬件上两种机制都需要检查，请分别各运行一遍本流程。
- `ethtool -k` 报告的、不在脚本已识别的六种特性（`rx-checksumming`、
  `tx-checksumming`、`generic-segmentation-offload`、
  `tcp-segmentation-offload`、`generic-receive-offload`、
  `tx-udp-segmentation`）之列的其他卸载特性。如果某块网卡暴露了其他相关
  特性（例如某些厂商特有的 `rx-udp-gro-forwarding` 或
  `tx-checksum-ip-generic` 标志），请在脚本中扩展 `RELEVANT_FEATURES` 和
  `OFFLOAD_MATRIX`。
