---
icon: material/lan-connect
---

# eBPF

!!! quote "sing-box 1.14.0 中的更改"

    eBPF 入站仍为实验功能，仅在带有 `with_ebpf` 编译标签的 Linux 和 Android
    构建中可用。

eBPF 入站透明接管选中的本机或下游 TCP/UDP 流量，被接管的连接仍进入 sing-box
常规路由流程。所需的系统网络状态由 sing-box 自动创建并清理。

eBPF 入站不使用[监听字段](/zh/configuration/shared/listen/)。

### 结构

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "tc_priority": 1,
  "fakeip_icmp": "off",
  "bypass_rule_set": [],
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "dns_mode": "respect_policy",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "bypass_port": [],
    "bypass_port_range": []
  },
  "shared": {
    "enabled": true,
    "data_plane": "packet_rewrite",
    "dns_mode": "respect_policy",
    "interface": ["wlan1"],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "bypass_port": [],
    "bypass_port_range": []
  }
}
```

### 字段

#### network

启用的传输协议，可选 `tcp` 和/或 `udp`，默认同时启用。

#### udp_timeout

UDP 会话超时，默认 `5m`。

#### tc_priority

TC filter 优先级，范围为 1 至 65535，默认 `1`。仅在需要与相同接口上的其他 TC
filter 协调顺序时修改。
保持默认值时，支持 TCX 的内核会优先使用 TCX link；配置自定义优先级时继续使用
传统 `clsact` 挂载，以保持数值排序语义。

#### bypass_rule_set

匹配这些规则集中目标 IP CIDR 的流量绕过此入站，非 IP 规则会被忽略。

#### fakeip_icmp

| 值 | 行为 |
| --- | --- |
| `off` | 不响应发往 FakeIP 地址池的 ICMP Echo Request，默认值。 |
| `reply` | 为发往已配置 FakeIP 地址池的 ICMP Echo Request 合成本地 Echo Reply。 |

`reply` 从不代理 ICMP：它只识别发往 FakeIP 地址池的 ICMP Echo Request，并立即
在本地原地合成 Echo Reply 作为响应，不会联系该请求 DNS 映射的真实目标。这使得
FakeIP 地址能够响应 `ping`，部分客户端以此判断目标是否可达。回复的源地址、
标识符、序列号和负载均与请求保持一致，且回复长度不会超过请求。因此该响应
反映的不是被代理目标的可达性或往返延迟，而只是本机自身的本地响应时间。

启用 `reply` 要求至少配置一个 FakeIP 前缀（IPv4 或 IPv6），并且至少存在下表中
一种可用的接管路径。若配置了 `reply` 但没有可用路径，将在启动时报错并指明不受
支持的组合，而不是静默失效。

`reply` 仅响应目标 ICMP 报文中可验证的安全子集：无选项且未分片的 IPv4，以及
前面没有扩展头的 IPv6 Echo。其余情况——包括分片报文、非 Echo 的 ICMP，或本对象
无法完整安全解析的报文——均原样放行。

##### 支持矩阵

| 数据面 | `fakeip_icmp: reply` |
| --- | --- |
| `local.data_plane: tc` | 支持 |
| `local.data_plane: cgroup` | 不支持本机流量 |
| `shared.data_plane: socket_assign` | 支持 shared 客户端 |
| `shared.data_plane: packet_rewrite` | 支持 shared 客户端 |

`local.data_plane: cgroup` 通过在报文构造之前改写 socket 目标地址来实现接管，
不挂载在任何网络接口上，因此没有可用来响应的位置——这是唯一被直接拒绝的组合。
两种 shared 数据面都会在各自的接口上挂载同一个 responder 程序（分别通过各自的
后端——`socket_assign` 用 `TCBackend`，`packet_rewrite` 用
`SharedNetworkBackend`），因此任意一种都能单独响应 shared 客户端。

只有当启用组合中仍包含 `local.data_plane: cgroup` 时，支持能力才按路径分别
计算：

- `local: cgroup` + 任一 shared 路径可以启动，但只响应 shared 客户端；本机
  cgroup 内进程产生的流量不会收到 FakeIP ICMP 回复。

本机流量需要使用 `local.data_plane: tc`。两种 shared 数据面都能响应 shared
客户端；将 `local: tc` 与任一 shared 数据面组合即可覆盖两条路径。

即使路径本身受支持，客户端仍需可用的源地址，以及能够将请求送到 responder 的路由。
在 Android 上，移动数据和 Wi-Fi 之间的上游切换可能使热点撤销全局 IPv6 前缀和
默认路由。IPv6 是否继续可用取决于设备和新的上游网络，不能仅凭连接了 Wi-Fi 就
判断 IPv6 必然失效。

撤销后，客户端仍可能保留 link-local IPv6 通信。在一组 Android 热点连接 Windows
的实测中，显式指定 link-local 源地址并添加经过热点的诊断路由后，FakeIP IPv6
请求获得了 4/4 个回复。改用旧的全局源地址时，Android 侧能抓到请求和已生成的回复，
但回复未送达 Windows。这区分了 responder 的工作状态与所测设备热点路径的交付能力，
link-local 测试成功并不代表普通客户端的 shared IPv6 流量仍然可用。

排查 RA 变化时，应分别检查 Router Lifetime，以及前缀信息选项中的 Preferred
Lifetime 和 Valid Lifetime。Router Lifetime 为 0 仅撤销默认路由器角色，不会
单独使客户端地址失效。标记为 deprecated（弃用）的地址仍是有效地址，仍须正常接收
报文，不能仅凭该状态解释丢包。应结合地址、路由、RA 字段和热点两端的抓包定位。
参见 [RFC 4861 第 4.2 节](https://www.rfc-editor.org/rfc/rfc4861.html#section-4.2)
和 [RFC 4862 第 5.5.4 节](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.5.4)。

Echo Reply 应返回请求的原始源地址。将回复目的地址改成客户端的另一个地址不能修复
已撤销的前缀，还可能使客户端无法将回复关联到原请求。

`local.data_plane: tc` 在另一个方向上有对应的前提：`local_reply` 只能看到系统
路由已经正常发送到本机 TC 接口上的请求，所以本机 ping FakeIP 网段需要本机自己
在该接口上有某条 IPv6 路由——哪怕只是一条默认路由就够了，跟 IPv4 场景一样，不
需要专门匹配 FakeIP 前缀的路由。当 `local.ipv6` 和 `fakeip_icmp: reply` 都启用、
但没有这样一条路由时，sing-box 会在启动时、以及之后每次本机接口发生变化时，打
一条指明具体接口名的警告日志，而不是让本机 IPv6 ping 静默超时、日志里什么线索
都没有。这是警告而不是启动报错，因为路由缺失属于普通的、会自行变化的网络状态
（不同于 `local.data_plane: cgroup`——那种情况下无论什么网络都不可能支持
`fakeip_icmp`），一旦本机获得真正的 IPv6 连通性就会自动恢复。

### local

#### local.enabled

启用本机产生流量的接管。只要任一路径使用了新的 `enabled` 字段，另一路径省略
`enabled` 时即视为 `false`。至少需要启用一条路径。

默认的 cgroup 数据面接管当前可见 cgroup v2 层级中的 socket，不依赖网络接口。
可选的 TC 数据面跟随系统当前默认网络接口；默认网络变化时会自动切换，没有可用默认
接口时会保留旧 attachment，待新接口准备好后切换。

#### local.data_plane

选择本机接管的数据面。默认值 `cgroup` 接管当前可见 cgroup v2 层级中的 socket；
如需在当前默认接口接管流量，应显式配置 `tc`。

#### local.cgroup_path

将 `data_plane: cgroup` 的接管范围限制到指定的绝对 cgroup v2 子树。省略时接管
当前可见的 cgroup v2 根层级及其所有子 cgroup。它不是 sing-box 服务自身 cgroup
的配置项，除非用户确实只希望接管该服务子树。

#### local.dns_mode

| 值 | 行为 |
| --- | --- |
| `hijack` | 接管已启用 TCP/UDP 协议的目标端口 53 流量。 |
| `respect_policy` | 先应用本机 UID 与包名选择，再接管目标端口 53。 |
| `off` | 不接管目标端口 53。 |

默认值为 `respect_policy`。该设置仅应用于已启用的 TCP/UDP 协议，不识别 DoH 或
DoT 流量。

#### local.ipv6

启用本机 IPv6 接管，默认 `true`。禁用后，本机 IPv6 流量绕过此入站。

#### local.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

#### local.include_uid

需要接管的 UID。只要配置了 include UID、UID 范围或包名，其他 UID 默认绕过。

#### local.include_uid_range

需要接管的 UID 范围，格式为 `start:end`。

#### local.exclude_uid

需要绕过的 UID。exclude 策略优先于 include 策略。

#### local.exclude_uid_range

需要绕过的 UID 范围，格式为 `start:end`。

#### local.include_android_user

需要接管的 Android 用户 ID，仅 Android。

#### local.include_package

需要接管的 Android 包名，仅 Android。

#### local.exclude_package

需要绕过的 Android 包名，仅 Android。无法区分共用同一 UID 的包。

#### local.bypass_port

绕过本机接管的目标端口。local `tc` 和 `cgroup` 两种数据面均支持；启用的
`network` 协议（TCP 和/或 UDP）分别适用。该选项只匹配目标端口。FakeIP 始终强制
接管。DNS 处理也优先于此设置：`hijack` 始终接管 53 端口，`respect_policy` 先应用
UID 策略再处理 DNS，`off` 已经绕过 DNS。配置 53 端口时 sing-box 会在启动时告警。

#### local.bypass_port_range

需要绕过的目标端口范围，格式为 `start:end`，范围包含两端端口。

### shared

#### shared.enabled

启用从配置的下游接口进入流量的接管。

#### shared.data_plane

| 值 | 行为 |
| --- | --- |
| `socket_assign` | 将选中的流量直接分配给内部透明监听器。 |
| `packet_rewrite` | 将选中的流量改写到内部 token 地址，并在下游接口恢复回复报文。默认值。 |

`packet_rewrite` 要求下游接口使用以太网帧，不使用 `socket_assign` 所需的策略路由。
两种 shared 数据面均不会创建 local TC 使用的 delivery veth。local 与 shared 数据面
可以独立选择。

#### shared.dns_mode

取值与 `local.dns_mode` 相同。`respect_policy` 模式会先应用来源 CIDR 与 MAC
选择，再接管目标端口 53。

#### shared.interface

==启用 shared 接管时必填==

客户端流量进入本机的下游接口。默认的 `packet_rewrite` 数据面要求接口使用以太网
帧；Ethernet/IPoE、raw-IP（包括 Android rmnet）、PPP/PPPoE 或 IPIP/SIT/GRE 隧道接口应显式配置
`socket_assign`。也可同时配置多个接口。暂时不存在的接口会在网络更新后重试，
当某个接口成为当前默认上游时，会停止其 shared 接管；该接口重新作为下游后自动
恢复。不接受 loopback。

#### shared.ipv6

启用 shared IPv6 接管，默认 `true`。禁用后，shared 接口上的 IPv6 流量绕过此入站。

在 Android 上，`shared.ipv6: true` 只启用接管，不会为热点客户端分配 IPv6 地址
或发送路由器通告。普通客户端使用 shared IPv6，依赖 Android 实际向客户端提供
可用的 IPv6 地址和路由。若上游切换撤销了热点的全局前缀和默认路由，客户端的普通
IPv6 连通性可能丢失，而 link-local 通信仍可能可用。启用 `shared.ipv6` 或
`fakeip_icmp` 无法恢复这些已撤销的网络配置。

已报告的移动数据上游实测支持 shared IPv4 和 IPv6。Wi-Fi 上游下能否双栈工作，
仍取决于热点是否保留有效的 IPv6 配置和可用的交付路径，不能由上述 link-local
诊断测试推导为已验证。仅撤销 IPv6 前缀或路由不会影响 shared IPv4。

#### shared.bypass_private_address

绕过私有和特殊用途目标地址，默认 `true`。

#### shared.include_source_cidr

需要接管的客户端来源 CIDR。列表非空时，不匹配的来源绕过。

#### shared.exclude_source_cidr

需要绕过的客户端来源 CIDR。exclude 策略优先于 include 策略。

#### shared.include_mac_address

需要接管的 48 位客户端来源 MAC 地址。

仅适用于使用以太网帧的 shared 接口。

#### shared.exclude_mac_address

需要绕过的 48 位客户端来源 MAC 地址。exclude 策略优先于 include 策略。

仅适用于使用以太网帧的 shared 接口。

#### shared.bypass_port

绕过 shared 接管的目标端口。`socket_assign` 和 `packet_rewrite` 两种 shared 数据面
均支持；启用的 `network` 协议（TCP 和/或 UDP）分别适用。该选项只匹配目标端口；
FakeIP 和 DNS 的优先级与 `local.bypass_port` 相同，配置 53 端口时会在启动时告警。

#### shared.bypass_port_range

需要绕过的目标端口范围，格式为 `start:end`，范围包含两端端口。

!!! note

    shared 模式不会启用 IP 转发，也不提供 NAT、DHCP、IPv6 路由器通告或热点管理。
    请在 Android、Linux 或路由器系统中配置这些功能。可以同时配置 Wi-Fi、USB
    网络共享等多个下游接口。

### 示例

以下三种配置均通过了 `sing-box check` 验证；它们所选用的接管路径
（`local.data_plane: tc`/`cgroup`、`shared.data_plane: socket_assign`/
`packet_rewrite`）均由本项目自身的真实内核网络命名空间测试覆盖。`check` 只验证
配置结构与对象构造是否正确，并不会附加到真实网络接口上。

##### 仅本机代理

接管本机自身产生的流量。`local.data_plane` 默认是 `cgroup`；若本机流量需要
`fakeip_icmp: reply`，请显式设置为 `tc`。

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "local": {
    "enabled": true
  }
}
```

##### 仅热点/网络共享

接管从 `wlan1`（请替换为实际的热点/网络共享接口名）下游客户端到达的流量，不启用
本机接管。`shared.data_plane` 默认是 `packet_rewrite`，要求以太网帧；对于
PPP/PPPoE、raw-IP 或隧道接口，请改用 `socket_assign`。两种 shared 数据面都
支持为这些客户端启用 `fakeip_icmp: reply`（参见上文支持矩阵）——按下方组合
示例的方式加上它和 FakeIP DNS 传输方式即可，无需其他改动。

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "shared": {
    "enabled": true,
    "interface": ["wlan1"]
  }
}
```

##### 本机与热点组合

两条路径同时启用，各自使用默认值。`local: tc` 加任一 shared 数据面即可让
`fakeip_icmp: reply` 同时覆盖两条路径——参见上文的支持矩阵；只有 `local: cgroup`
会让本机流量得不到响应。`fakeip_icmp: reply` 要求 `dns.servers` 中配置了
FakeIP DNS 传输方式，因此以下示例给出了完整配置，因为缺少该项 `sing-box check`
会拒绝 `reply`。

```json
{
  "inbounds": [
    {
      "type": "ebpf",
      "tag": "ebpf-in",
      "fakeip_icmp": "reply",
      "local": {
        "enabled": true,
        "data_plane": "tc"
      },
      "shared": {
        "enabled": true,
        "data_plane": "socket_assign",
        "interface": ["wlan1"]
      }
    }
  ],
  "dns": {
    "servers": [
      { "type": "udp", "tag": "remote", "server": "8.8.8.8" },
      { "type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18" }
    ],
    "rules": [
      { "query_type": ["A", "AAAA"], "server": "fakeip" }
    ],
    "final": "remote"
  },
  "outbounds": [
    { "type": "direct" }
  ]
}
```

### 资源限制

- **UDP 应答 socket**：客户端通过 TC/shared 数据面（不包括
  `local.data_plane: cgroup`，它从不打开这类 socket）到达的每个不同目的地会
  占用一个透明 UDP 应答 socket，按内部分片限制为每片 256 个（共 16 片，合计
  4096 个）。达到容量上限时优先回收一个空闲 socket；若没有可回收的，新目的地
  的应答会被拒绝而不是继续扩容。此外，一个空闲达 5 分钟的 socket 会被后台每
  分钟一次的清扫任务独立回收，无需等待容量压力触发。以上均不可配置；默认值
  是按常规客户端规模设定的，并未针对具体部署调优。
- **绕行 CIDR / 主机地址策略**：各后端编译后的绕行 CIDR 与主机地址策略表都有
  容量上限（数万条目级别）；超出上限会在启动或更新时报错，而不是被静默截断。
- 上述限制的目的是在持续负载和会引发状态漂移的事件（网络变化、反复失败）下
  保持内存与内核表使用量有界；运行时对应的压力指标见下方"诊断"一节的计数器。

### 诊断

以下两种工具回答的是两个不同的问题：

- **`sing-box tools ebpf status`** 探测的是*运行该命令的内核*支持什么——程序
  类型、helper、map 类型——不需要一个正在运行的 sing-box 实例。它无法判断一个
  *正在运行*的 eBPF 入站是否真的在接管流量，因为它从来没有一个运行中的实例可
  供读取。
- **Clash API 的 `GET /ebpf`** 端点（当配置了 Clash API 服务器时）从运行中的
  进程内部报告每个 eBPF 入站的实时状态：启用了哪些路径、每条路径实际挂载的
  接口与机制（`tcx` 或 `clsact`）、是否有路径仍在等待接口或正在从故障中恢复、
  最近一次警告及故障最近一次自行恢复的时间、各后端间 bypass_rule_set 的一致
  性、UDP 会话数与应答 socket 池状态，以及下文所述的分类计数器。例如：

  ```
  curl -H "Authorization: Bearer $SECRET" http://127.0.0.1:9090/ebpf
  ```

  同样这几项事实的简要版本（启用的路径、实际挂载方式、仍在等待接口的路径、
  `fakeip_icmp` 实际覆盖的范围）也会在启动时以默认可见的日志级别记录一次。

上报的计数器包括：TC assignment 查找失败次数、shared packet-rewrite 令牌
（token）分配失败次数与改写（rewrite）失败次数、shared packet-rewrite
reconcile 失败次数、恢复尝试/成功/失败次数，以及（启用 `fakeip_icmp: reply`
时）FakeIP ICMP 已发送的回复数、已检查但未回答而放行的 Echo Request 数、
改写失败数。这些计数从进程启动起累计，不会自行重置；要计算速率，取两次读数
相减即可。它们刻意不按客户端或目的地拆分（那样会随客户端来去无限增长），
也不会记录单个数据包。FakeIP ICMP 的放行计数只统计本对象检查过但未回答的
ICMP/ICMPv6 Echo Request（分片、带选项、类型/代码不符，或目的地不在 FakeIP
范围内）——绝不统计同一接口上的普通非 ICMP 流量。

### 限制

- 一个 sing-box 实例中只能有一个启用 local 接管的 eBPF 入站；其他 eBPF 入站必须
  仅启用 shared 接管。
- 已分片的 IPv4 和 IPv6 数据报绕过接管；IPv6 atomic fragment 作为普通 IPv6
  报文处理。
- 网络变化后会自动恢复接管状态。
- 每一个原地改写报文的 TC 程序（bypass_rule_set CIDR 匹配、
  `shared.data_plane: packet_rewrite`、`fakeip_icmp: reply`）都已针对
  network namespace 和 veth pair 测试验证过，但这两种环境都不会触发真实网卡
  的校验和或分段卸载（veth 完全没有硬件卸载路径，软件回环无论网卡特性如何
  声明，都会如实计算校验和）。在依赖此入站运行于尚未验证过硬件卸载与 eBPF
  改写报文交互行为的实体机之前，请阅读
  [eBPF 校验和/卸载验证](/zh/manual/misc/ebpf-checksum-offload-verification/)。

在供应商内核或 Android 内核上启用前，请阅读
[eBPF 内核要求](/zh/manual/misc/ebpf-kernel-requirements/)。
