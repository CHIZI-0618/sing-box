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

## 角色

早期版本的这套流程完全由被测主机自己发起流量，独立审查指出这样根本无法
验证 `shared.data_plane`：被测主机自己发出的流量只会经过
`local.data_plane` 的 TC **egress** 分类器，永远不会经过
`shared.data_plane` 的 **ingress** 分类器——后者只会看到真正从下游客户端
到来的流量。现在这套流程明确区分三种角色：

- **DUT（被测主机）**：运行待测 eBPF 入站的主机，接到 `$LOCAL_IFACE`
  网卡。脚本本身就在这台主机上运行。
- **`$REMOTE_HOST`**：DUT 可达的一个真实、非 FakeIP 的目的地，可通过
  SSH 访问。用于 `bypass_rule_set` 的对照场景（预期完全不受影响的流量），
  以及在检查 `local.data_plane` 时，作为 DUT 自身经由 local egress
  路径通信的对象。
- **`$DOWNSTREAM_HOST`**（仅在检查 `shared.data_plane` 时需要）：DUT
  面向下游一侧的接口可达的另一台主机，用来扮演真实 LAN 客户端。所有
  `shared.data_plane` 检查都从这台主机经 SSH 朝 FakeIP 目标发起——绝不
  从 DUT 自己发起，否则会在不知不觉中又测回 `local.data_plane` 自己的
  代码路径。

如果 DUT 上同时启用了 `local.data_plane` 和 `shared.data_plane`，仅凭
"下游发起的请求收到了正确回复"并不能单独证明是 `shared.data_plane` 处理
的——见下文 `$DUT_DIAGNOSTICS_URL` 一节，这是唯一能真正区分两者的手段，
也附带说明了它自身的局限。如果这种归因很重要，请在 DUT 上只启用待测的
那一个角色。

早期版本的这套脚本无论文档要求 DUT 上禁用哪个角色，每次运行都会无条件
同时执行由 DUT 自己发起的 (`local.data_plane`) 检查和由 `$DOWNSTREAM_HOST`
发起的 (`shared.data_plane`) 检查——如果 DUT 按文档建议只启用了
`shared.data_plane`（这本身是合法的、第一级支持的部署形态），本机到
FakeIP 的 ping 根本没有 local responder 可用，无条件运行的本机检查就会
失败，从而拖垮整次运行，即便 `shared.data_plane` 本身工作完全正常。
`$TEST_ROLE`（见下文）现在用来选择这两者中实际运行哪一个，这样纯
shared 部署的 DUT 就能被干净地验证，而不必为了迁就本脚本而额外启用
`local.data_plane`。

## 所需环境

- 两台由真实网卡连接的 Linux 主机（DUT 和 `$REMOTE_HOST`）——物理以太网
  链路，或配置为 SR-IOV 直通进虚拟机的数据中心网卡。用
  `ethtool -i <iface>` 确认驱动是真实硬件驱动（`ixgbe`、`i40e`、
  `mlx5_core`、`r8169`、`igc` 等——不是 `veth`、`virtio_net` 或
  `vmxnet3`）。如果要检查 `shared.data_plane`，还需要第三台主机
  `$DOWNSTREAM_HOST`，能从 DUT 面向下游的接口访问到。
- 涉及的每台主机都要有 root 权限，且 DUT 能以非交互方式（密钥认证）
  SSH 到 `$REMOTE_HOST`，如果用到 `$DOWNSTREAM_HOST` 也要能 SSH 过去。
- DUT 上安装 `ethtool` 和 `tcpdump`；涉及的每台主机都要安装 `nc`
  （netcat）。如果设置了 `$DUT_DIAGNOSTICS_URL`，DUT 上还要有 `jq` 和
  `curl`。
- DUT 已经运行着接到 `$LOCAL_IFACE` 网卡的 sing-box eBPF 入站，其配置
  覆盖本流程要检查的路径：
  - 启用 `fakeip_icmp: reply`，其 FakeIP 前缀与下面的 `$FAKEIP_PREFIX` 一致。
  - 如果同时设置了 `$REMOTE_PORT_TCP` / `$REMOTE_PORT_UDP` 和
    `$DOWNSTREAM_HOST`，需启用 `shared.data_plane: packet_rewrite`
    （用于覆盖来自真实下游客户端的 NAT/流改写路径）。
  - 让 `$REMOTE_HOST` 的流量经过本入站路由，这样若配置了
    `bypass_rule_set` 就有真实的匹配流量可供评估。
  - 如果要检查 `shared.data_plane`，可以顺便启用 Clash API 服务器，把
    `$DUT_DIAGNOSTICS_URL` 指向它的 `/ebpf` 路由（参见
    [eBPF 入站问题排查](/zh/manual/misc/ebpf-troubleshooting/)），这样
    脚本就能确认 DUT 自身的计数器确实发生了变化，而不只是"来了个回复"。

## 运行方式

```sh
sudo LOCAL_IFACE=eth0 \
    REMOTE_HOST=192.0.2.10 \
    REMOTE_SSH_USER=root \
    DOWNSTREAM_HOST=192.0.2.20 \
    DOWNSTREAM_SSH_USER=root \
    DUT_DIAGNOSTICS_URL=http://127.0.0.1:9090/ebpf \
    FAKEIP_PREFIX=198.18.0.0/15 \
    REMOTE_FAKEIP_TARGET=198.18.0.1 \
    REMOTE_IPV6=fdfe:dcba:9876::1 \
    REMOTE_PORT_TCP=15000 \
    REMOTE_PORT_UDP=15001 \
    TEST_ROLE=both \
    common/ebpf/testing/checksum_offload_verify.sh
```

只有 `LOCAL_IFACE`、`REMOTE_HOST`、`FAKEIP_PREFIX`、`REMOTE_FAKEIP_TARGET`
是必需的。`$TEST_ROLE` 决定本次运行实际检查哪个数据面，默认为 `both`：

- `local` —— 只运行 `local.data_plane` 的检查，由 DUT 自己发起，
  不需要 `$DOWNSTREAM_HOST`。
- `shared` —— 只运行 `shared.data_plane` 的检查，由 `$DOWNSTREAM_HOST`
  发起，此时必须设置该变量，脚本会在启动前直接拒绝缺少它的情况（如果
  改由 DUT 自己发起 shared 检查，会在不知不觉中又测回
  `local.data_plane` 的代码路径，这正是该选项要防止的错误）。
- `both`（默认）—— 两个角色的检查都运行；同样要求设置
  `$DOWNSTREAM_HOST`。

被排除的角色会在报告里记为 `NOT_TESTED`，而不是被默默省略，因此一次
只测 `local` 或只测 `shared` 的运行，其报告仍然会明确说明自己没有检查
什么。其余变量用于收窄或扩大检查范围（完整列表及默认值见脚本自身的头部
注释）。该脚本会：

1. 通过 `ethtool -k` 读取并记录 `$LOCAL_IFACE` 当前的卸载特性标志，以便在
   退出时（包括 Ctrl-C 中断时）精确恢复。
2. 默认运行四种卸载组合——全部相关特性打开、全部关闭、仅关闭 TX 校验和、
   仅关闭 TSO/GSO。这是完整 2^6 幂集中特意精简出的一小部分："全部打开"是
   默认生产场景，"全部关闭"用于隔离验证 eBPF 改写本身是否正确（与任何卸载
   无关），另外两个单特性场景则分别隔离出最可能与原地报文头改写产生不良
   交互的两种卸载（TX 校验和插入会假设校验和字段中已经是软件本应计算出的
   值；分段卸载则假设这是驱动要为其复制报文头的单一逻辑报文）。每个组合都
   显式列出全部六种已识别特性的取值——早期版本里，一个组合如果只写出自己
   关心的特性，会悄悄继承上一个组合遗留下来的其他特性状态，导致"只关闭
   TX 校验和、其余全开"和"只关闭 TX 校验和、其余保持上一轮遗留状态"在报告
   里完全无法区分。如果某块网卡或驱动需要更细的覆盖，可在脚本中扩展
   `OFFLOAD_MATRIX`，但每一条都要保持这种完整写法。
3. 每次尝试设置后都用 `ethtool -k` 把状态读回来核对。如果网卡最终并未
   真正进入某个组合名称所声称的状态——这块网卡不支持该特性，或者驱动
   悄悄拒绝/忽略了这次修改——该组合会在报告里整体记为 `UNSUPPORTED`，
   且不会运行任何该组合下的流量检查，而不是像早期版本那样仍然在一个已经
   不再对应真实状态的标签下继续跑并写出结果。
4. 对每一个真正生效的组合，运行并（在 DUT 和 `$REMOTE_HOST` 上通过
   `tcpdump`）抓包：
   - 一次从 DUT 经普通 SSH 连接到 `$REMOTE_HOST` 的对照传输（完全不经过
     任何 eBPF 改写，只检验该网卡及其卸载设置本身——如果这一步失败，
     说明问题出在网卡/驱动组合本身，与本入站无关）。
   - 如果 `$TEST_ROLE` 为 `local` 或 `both`：`local.data_plane` 自身的
     FakeIP ICMP echo（IPv4，若设置了 `$REMOTE_IPV6` 则还有 IPv6），以及
     （若设置了 `$REMOTE_PORT_TCP` / `$REMOTE_PORT_UDP`）TCP/UDP
     传输——全部由 DUT 自己发起，朝向 `$REMOTE_FAKEIP_TARGET`。如果
     `$TEST_ROLE` 为 `shared`，这些检查会被跳过并记为 `NOT_TESTED`。
   - 如果 `$TEST_ROLE` 为 `shared` 或 `both`：再做一遍同样的三项检查，
     但改为从 `$DOWNSTREAM_HOST` 经 SSH 发起，而不是从 DUT 发
     起——这才是真正检验 `shared.data_plane` 的部分。如果 `$TEST_ROLE`
     为 `local`，这些检查会被跳过并记为 `NOT_TESTED`。如果同时设置了
     `$DUT_DIAGNOSTICS_URL`，这几项检查还会额外要求 DUT 自身的对应
     计数器（ICMP 检查看 `fakeip_icmp_replies`，TCP 检查看
     `rewrite_failures` 保持不变）按真实、正确处理报文时应有的方式变化，
     而不只是 `$DOWNSTREAM_HOST` 收到了什么。
5. 将 PASS/FAIL/UNSUPPORTED/NOT_TESTED 记录到 `$OUT_DIR/report.tsv`，判定
   依据是**接收端**主机内核实际接受了什么，以及对 TCP/UDP 传输而言是否
   真正正确地收到了——而不是发送端 `tcpdump` 自身给出的校验和判定。TCP
   和 UDP 检查会比较发送内容和接收端各自算出的 SHA-256，而不再只看
   字节数：早期版本只要接收端收到任何非零字节就判为"received
   intact"，独立审查指出这样即便传输被截断、被破坏，甚至发送命令自己
   已经失败，只要另一端出现了"什么东西"，也会记为 PASS。UDP 本质上是
   尽力而为的，因此一个报文完全没有到达（接收端文件始终为空）会在判为
   失败前重试最多三次；但如果报文确实到达了，只是哈希对不上发送内容，
   则在那一次尝试上立即判为 FAIL，绝不重试——因为这是数据损坏而不是
   单纯丢失，重试掉它反而会掩盖本流程本来就是要抓的那个缺陷。这是对
   整个 payload 的内容校验，而不是带独立丢失/乱序/损坏阈值的逐包序号
   校验——它证明了到达的字节与发出的字节完全一致（或者不一致），这正是
   这里"校验和/内容完整性"的含义；它并不额外刻画单次传输内部的乱序
   情况。在网卡自身的校验和引擎完成工作之前抓到的包，即使真实的接收方
   完全正常接受，也常常被标为"incorrect"；这是"在 TX 卸载生效之前抓包"
   这件事本身的特性，并不是真实缺陷——如果把它当作缺陷来判定，无论 eBPF
   改写是否正确，每次运行都会被判为失败。这正是为什么本流程以接收端
   自身的接受/丢弃行为和内容哈希为准，而完全不把 `tcpdump` 的内联校验和
   判定作为通过/失败信号——它只在其他判定已经失败时，作为附加在报告里
   的原始证据使用。
6. 把报告自身的状态列读回来精确计数 `PASS`、`FAIL`、`UNSUPPORTED`、
   `NOT_TESTED` 各有多少条——而不是在细节文字里搜索"FAIL"这个词——并打印
   一行摘要，用五种不同的退出码之一：`0`（至少一条 `PASS`、零条
   `FAIL`、零条 `UNSUPPORTED`——干净通过）、`1`（存在至少一条
   `FAIL`，优先于其他所有情况被检查）、`2`（`INCONCLUSIVE`：整次运行
   一条 `PASS` 都没有，意味着本次运行实际上什么都没有验证过——例如所有
   组合都是 `UNSUPPORTED`，比如这块网卡/驱动组合根本不支持某个必需的
   `ethtool` 特性）、`3`（`PARTIAL`：至少有一条 `PASS`，但同时至少
   有一条 `UNSUPPORTED`，意味着预期的覆盖范围只跑了一部分），或 `4`
   （`FATAL`：到了最后这一步，报告文件本身却读不回来了，尽管整次运行
   过程中一直在往里面写——这和 `INCONCLUSIVE` 是完全不同的结论，后者
   是指报告读取正常、但里面确实没有任何 `PASS`）。早期版本
   的这套脚本只在报告里搜索字面上的"FAIL"；如果所有组合都是
   `UNSUPPORTED`（`ethtool` 不可用，或网卡缺少某个必需特性），报告里
   根本没有 `FAIL` 这一行可找，脚本便打印"all recorded checks
   PASSed"并以 `0` 退出，尽管实际上一个包都没有真正检查过。现在这个
   脚本的退出码 `0` 专指"确实跑了真实流量检查，且全部通过"——绝不再是
   "什么都没跑所以没有失败"。

## 如何解读失败

- **运行以 `4`（`FATAL`）退出**：整次运行过程中一直在写入的报告文件，
  到了最后这一步却读不回来了。这和 `INCONCLUSIVE` 不是一回事，也不
  意味着"什么都没通过"——它的意思是这次运行连汇总结果都算不出来。请
  检查 `$OUT_DIR`/报告文件是否在脚本运行期间被别的东西删除、移动，或
  改动了权限。
- **运行以 `2`（`INCONCLUSIVE`）退出**：整次运行没有任何一项检查真正
  通过——最可能的原因是所有组合都是 `UNSUPPORTED`。这不能作为 eBPF
  改写正确的证据；因为什么都没有被验证过。先解决导致每个组合都无法
  生效的问题（看 stderr 上的 `UNSUPPORTED` 警告），再重新运行后才能
  下结论。
- **运行以 `3`（`PARTIAL`）退出**：至少有一项检查通过了，但至少有一个
  组合是 `UNSUPPORTED`，没有贡献任何结果。请查看摘要行和报告，确认
  具体哪些组合从未运行，并把它们明确当作未验证处理——不要把某个已通过
  组合的结果外推到一个从未真正测试过的网卡状态上。
- **某个组合被记为 `UNSUPPORTED`**：网卡或驱动实际上没有真正进入该组合
  名称所声称的状态——具体是哪个特性，看脚本应用该组合时写到 stderr 的
  警告。这与 eBPF 改写本身无关，该组合下的检查也都没有运行。
- **某项检查被记为 `NOT_TESTED`**：`$TEST_ROLE` 在本次运行中刻意排除
  了它（只测 `local` 的运行会让每一条 `shared_*` 检查都是
  `NOT_TESTED`，反之亦然）。这也不是一个发现——如果需要覆盖被排除的
  角色，请设置 `TEST_ROLE=both`（并配好 `$DOWNSTREAM_HOST`）后重新
  运行。
- **对照传输在某个（已生效）组合下失败**：说明这块硬件上的网卡/驱动组合
  本身无法在该卸载组合下正常工作——与 eBPF 无关。应先修复该网卡/驱动
  固件组合（或直接排除该组合），再对 eBPF 改写路径下结论。
- **对照传输通过，但某个 `local_*` 或 `shared_*` 检查在同一组合下失败**：
  这正是本流程要捕捉的真实发现——某个 eBPF 改写后的报文，在该卸载组合下、
  在失败检查所对应的那个数据面上，在线路上确实是错误的。请将 `$OUT_DIR`
  下 DUT 和 `$REMOTE_HOST` 的 `.pcap` 文件一并附到报告中；应优先查看
  接收端的抓包（而不是发送端的），因为它才是真正经过了网卡实际校验和
  计算之后的那一份。
- **`shared_fakeip_icmp` 检查失败，具体原因是 DUT 的计数器没有变化**，
  而 `$DOWNSTREAM_HOST` 自己确实收到了看起来正确的回复：说明回答这次
  ping 的不是本入站的 `shared.data_plane`（可能是同一网段上的其他设备，
  或者如果同时启用了 `local.data_plane`，是它回答的——见上文"角色"一节）。
  这是需要修正的测试搭建问题，不是关于 eBPF 改写本身的证据，无论朝哪个
  方向。
- **打开和关闭所有卸载特性都全部通过**：说明本轮所检查的代码在这块网卡上，
  并不以这套流程能检测到的方式依赖其卸载行为。请把网卡型号、驱动和固件
  版本随 PASS 结果一并记录下来——换一块网卡/驱动仍然是一个待验证的问题，
  这一次干净的运行结果并不能替所有设备回答它。

## 本流程未覆盖的范围

- Android 硬件。本流程是按 Linux 主机的场景编写的；Android 的网络栈、
  驱动模型和可用工具（`nc`、`tcpdump` 是否可用、`ethtool` 支持程度）差异
  大到需要在真实设备上单独走一遍，而不是直接照搬本脚本。
- TCX 相关的卸载交互。脚本本身不选择挂载机制（TCX 还是 `clsact`）——这由
  DUT 上已经在运行的 sing-box 配置决定，而不是由本脚本决定。如果同一
  硬件上两种机制都需要检查，请分别各运行一遍本流程。
- `ethtool -k` 报告的、不在脚本已识别的六种特性（`rx-checksumming`、
  `tx-checksumming`、`generic-segmentation-offload`、
  `tcp-segmentation-offload`、`generic-receive-offload`、
  `tx-udp-segmentation`）之列的其他卸载特性。如果某块网卡暴露了其他相关
  特性（例如某些厂商特有的 `rx-udp-gro-forwarding` 或
  `tx-checksum-ip-generic` 标志），请在脚本中扩展 `RELEVANT_FEATURES` 和
  `OFFLOAD_MATRIX`——一旦扩展，`OFFLOAD_MATRIX` 里每一条都要继续显式
  列出 `RELEVANT_FEATURES` 的全部取值。
- DUT 上同时启用 `local.data_plane` 和 `shared.data_plane` 时的完整归因：
  `$DUT_DIAGNOSTICS_URL` 的计数器是所有承载 `fakeip_icmp` 的数据面
  加总得到的，不按角色拆分。如果需要明确的判定，请在 DUT 上关闭当前
  不是被测对象的那个角色。
