# why-slow

**tcping tells you it's slow. `why-slow` tells you why.**

`why-slow` is a cross-platform network **diagnosis** CLI. It runs structured probes and prints a
verdict with evidence — not just a latency number. Single static binary, zero external
dependencies, standard library only.

[![Go](https://img.shields.io/badge/go-1.27.1-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![CI](https://github.com/A015cc/why-slow/actions/workflows/ci.yml/badge.svg)](https://github.com/A015cc/why-slow/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/A015cc/why-slow?sort=semver&display_name=tag)](https://github.com/A015cc/why-slow/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Why not tcping?

[`pouriyajamshidi/tcping`](https://github.com/pouriyajamshidi/tcping) is a good tool, and a mature
one. It measures TCP latency well, it is widely used, and if your question is simply *"how many
milliseconds is this TCP port, and does it stay up?"* you should use it — it does that job better
than a new tool will, and there is no reason for this project to re-implement it.

But a latency number is a **measurement**. It is not a **diagnosis**. A summary like *"mean 23 ms,
4 % of probes above 1000 ms"* tells you that something is wrong. It does not tell you whether
that something is packet loss on the path, a stateful middlebox, a saturated server accept queue,
or traffic quietly leaving through a VPN tunnel. Those are different problems with different
fixes, and the raw numbers look similar for all of them.

The two genuinely hard problems after "it's slow" are:

1. **Attribution** — deciding which of those causes the data actually supports.
2. **Restraint** — not claiming a cause the data cannot support.

`why-slow` collects the same class of handshake timings, then does the analysis that turns them
into findings. The difference is entirely in what comes *after* the sampling.

| | tcping | why-slow |
|---|---|---|
| Primary output | latency samples and summary | verdict, findings, confidence |
| Question answered | *how slow is it?* | *why is it slow?* |
| Bimodality | reported as jitter / loss % | tested against the TCP retransmission ladder |
| A/B comparison | sequential, order-sensitive | interleaved, paired sign test |
| Path / egress | not inspected | interface and TUN/VPN attribution |
| NAT | not inspected | local / gateway / public comparison |
| Honesty | n/a | confidence and severity reported as separate axes |

## What it looks for

Each capability below exists because a specific real diagnostic question could not be answered by
looking at a latency number alone.

### 1. Bimodal latency checked against the TCP retransmission ladder

On a lossy link the samples are not a left-leaning jitter distribution. A few samples cluster
around `baseline + 1s` while the rest sit at the baseline. That gap is not arbitrary: it is a TCP
initial retransmit. The initial RTO is quantized (RFC 6298, which superseded RFC 2988's 3 s), so
the cumulative backoff ladder is **1 s / 3 s / 7 s / 15 s** on Linux and Windows 10/11, or
**3 s / 9 s / 21 s** on older Windows Server releases.

This quantization is the single strongest piece of evidence available from `connect()` timing. A
genuinely slow server produces a *shifted or smeared* mode; it does not produce a mode pinned to
`baseline + exactly 1.000 s`. `why-slow` locates the split between modes with the largest gap in
the data, then validates that split against the physical ladder — a cluster only counts if it
lands on a real rung and is tight enough to be quantized. Blind clustering at these sample sizes
would happily fit a mode to a single outlier; requiring ladder alignment is what prevents that.

### 2. Interleaved A/B comparison with a paired sign test

Comparing two endpoints sequentially (all of A, then all of B) is misleading: transient link
state makes any A-then-B comparison show spurious differences that belong to the moment, not to
the endpoint. `why-slow` samples **A, B, A, B, …** and reports a **paired sign test** over the
matched pairs, so each comparison is made against the same link conditions.

> In one development case a sequential test concluded that one endpoint was ~3× worse than
> another. Re-running with interleaved sampling gave **p = 0.42** — no real difference at all.
> The first result was an artifact of order.

### 3. Path and egress attribution

Which interface does traffic to the target actually leave through, and is that interface real
hardware or a virtual adapter? If egress goes through a TUN/TAP device (WireGuard, OpenVPN,
Tailscale, Clash, sing-box, a game accelerator, …), then the latency being measured may describe
the tunnel, not the underlying link — and that changes what every other number means. `why-slow`
classifies adapters by name and names the tunnel it finds.

### 4. CGNAT evidence

`why-slow` compares the local address, the gateway address and the public address you are seen as.
A gateway inside `100.64.0.0/10` (RFC 6598) is a clean signal that the ISP is NATing too, which
means inbound connections are impossible without a relay or hole-punching. The public-IP lookup
deliberately **bypasses any system or environment proxy**: a machine behind a local proxy would
otherwise report the VPS's address as its own, which would invert the diagnosis rather than
merely blur it.

### 5. IPv6 readiness

An address being present does not mean IPv6 works. `why-slow` checks whether a **global unicast**
address (`2000::/3`) exists, whether a default route for it exists, and whether it can actually
carry traffic — and it labels addresses by role, so `fe80::` link-local, `fc00::/7` unique-local,
Teredo and 6to4 can be told apart from real global connectivity.

## The honesty contract

This is the part that matters most, so it is stated up front rather than buried.

`why-slow` reports **Confidence** and **Severity** as two orthogonal axes. A finding can be
severe *and* uncertain, and the report says both:

- **Severity** is how much the finding hurts you: `info`, `notice`, `warning`, `critical`.
- **Confidence** is how sure the tool is: `low`, `medium`, `high`.

`connect()` timing alone cannot *prove* that a SYN was dropped. A stateful middlebox, a full
server accept queue (SYN-cookie handling), and a server whose softirq path is starved can all
produce a similar shape. So findings are written in the **"consistent with"** register —
*"timings are consistent with a retransmit"*, never *"the SYN was dropped"* — and the named
confounders are printed alongside the claim.

Confidence is calibrated deliberately:

- `medium` — a single ladder rung is occupied, with enough samples to separate modes and a clean
  split.
- `high` — **two or more** ladder rungs are occupied, or the same signature replicates across
  independent targets. Two quantized modes that a slow server cannot fake are close to conclusive.
- Temporal clumping of the high samples (a runs test) is evidence *against* memoryless loss, and
  it **downgrades** the claim by one step.

If that restraint reads as the tool hedging, that is the point. A diagnostic that overclaims is
worse than no diagnostic: it sends you to fix the wrong thing. Refusing to overstate is a feature,
and it is the reason a verdict from `why-slow` is worth acting on.

## Install

### With the Go toolchain

```sh
go install github.com/A015cc/why-slow@latest
```

This puts a `why-slow` binary in `$(go env GOPATH)/bin`. Because the module has **no external
dependencies**, this needs no module proxy beyond the module itself.

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/A015cc/why-slow/releases). Archives are
provided for:

- **Windows** — `why-slow_<version>_windows_amd64.zip`, `..._windows_arm64.zip`
- **macOS** — `..._darwin_amd64.tar.gz` (Intel), `..._darwin_arm64.tar.gz` (Apple silicon)
- **Linux** — `..._linux_amd64.tar.gz`, `..._linux_arm64.tar.gz`

A `checksums.txt` is published with each release. Binaries are built with `CGO_ENABLED=0` and
`-trimpath`, so each one is a single static executable — small enough to `scp` to a VPS and run
there, which is often exactly what you want when the slow hop is not the machine you are sitting
at.

## Usage

```
why-slow                          run every probe and print one consolidated report
why-slow latency <host:port>      handshake timing, then ladder / loss analysis
why-slow path <host>              interface, route and egress attribution
why-slow nat                      local / gateway / public address comparison
why-slow ipv6                     IPv6 address, route and reachability check
```

Examples:

```sh
# 40 handshake samples against one endpoint
why-slow latency edge.example.net:443 -n 40

# interleaved A/B against a second endpoint, with a paired sign test
why-slow latency a.example.net:443 -n 40 --ab b.example.net:443

# where does traffic to this host actually leave from?
why-slow path example.net

# am I behind CGNAT?
why-slow nat

# can this host actually use IPv6?
why-slow ipv6

# everything at once
why-slow
```

Global flags:

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output; carries a versioned `schema_version` so scripts can pin against it |
| `--no-color` | disable ANSI colour (also honoured when the output is not a TTY) |
| `--timeout` | per-probe timeout (default 5 s for a dial, 10 s for HTTP lookups) |
| `--family 4\|6` | restrict probes to a single IP family |

### Example output

The block below is an **illustrative example** of the output format, not a measurement of any real
host, and not a benchmark.

```text
$ why-slow latency edge.example.net:443 -n 40

latency  edge.example.net:443        40/40 completed

  baseline    18.4 ms    IQR 1.1 ms    (n=36)
  cluster   1018.6 ms    IQR 6.2 ms    (n=4)   = baseline + 1000 ms rung

  ladder     modern (RFC 6298: 1/3/7/15 s)  rung 1000 ms occupied
             legacy (3/9/21 s)              no support
  split      clean (nothing stranded between the modes)
  temporal   interspersed (runs z = -0.4)   consistent with memoryless loss
  loss       10.0 %   (95 % Wilson CI 4.0 - 23.1 %)

  VERDICT    [warning] [confidence: medium]
  Handshake latency is bimodal: a minority of connects land ~1 s above
  baseline, quantized to the first TCP retransmission rung. Consistent
  with handshake packet loss, not a uniformly slow server.

  confounders named
    - a stateful middlebox or a full server accept queue can produce the
      same shape
    - two occupied rungs, or this signature on an unrelated target, would
      raise confidence to high
```

## Reading the output

**The ladder cluster is the finding; the percentiles are context.** The important line is not the
average — it is whether the upper mode sits *on a rung* (`baseline + 1000 ms`, `+3000 ms`, …) and
whether it is tight. A tight cluster on a rung is a physical signature. A broad upper mode is
congestion, and the tool says so instead of calling it loss.

**p95 is annotated at small n.** At `n = 40`, the 95th percentile is interpolated between the top
two samples, so moving a single sample can swing it by hundreds of milliseconds. That is not a
stable tail estimate, and the report marks it as such rather than letting you read it as one. When
you want the tail, the cluster and its rung tell you more than p95 does.

**Mean and standard deviation are demoted, on purpose.** On bimodal data the mean lands in the gap
*between* the modes, where no sample actually lives, and the standard deviation is dominated by
the distance between the modes — so it describes neither. Reporting `mean 118 ms ± 310 ms` for the
distribution above would be arithmetically correct and diagnostically useless. `why-slow` leads
with the baseline, the cluster, and the interquartile range of each.

**`confidence: medium` means: act on it, but verify the confounders.** Medium is the honest
reading of a single occupied rung. It says *"the shape matches a retransmit and nothing in this
run contradicts that"* — it does not say the cause is proven. Before you escalate, check the named
confounders; the fastest way to raise confidence is to run the same probe against an unrelated
target and see whether the same signature appears.

## What this cannot tell you

A diagnostic is only as useful as its stated limits.

- **CGNAT cannot be concluded from a single host.** `why-slow` runs on your machine, and your
  router's WAN address is not visible from there. Seeing a private or carrier-grade address on the
  inside is strong evidence of *some* NAT, but distinguishing local NAT from ISP CGNAT can require
  a view from outside or a second vantage point. The tool reports what it can see and stops short
  of the conclusion it cannot support.
- **A truncated dial timeout is not a slow sample.** A probe that hits the timeout is a
  *truncated* measurement, not a `>5 s` latency. Feeding it into the analysis would manufacture
  exactly the high mode the ladder test exists to find, so completed measurements and timeouts are
  kept strictly separate.
- **A single-host view cannot separate middlebox delay from server delay.** From one vantage
  point, "the SYN was delayed" and "the server was slow to accept" look alike. Separating them
  needs a second vantage point or a capture at one end. `why-slow` names middlebox behaviour as a
  confounder rather than guessing.
- **It is a handshake instrument.** It times connection setup, not throughput, not application
  latency, not a full transfer. A path can have clean handshakes and terrible throughput; this
  tool will not see that.
- **`connect()` timing bounds what any conclusion can claim.** Everything above follows from that
  one sentence.

## Status

The statistical layer (cluster detection, the ladder test, the Wilson interval, the runs test) is
unit-tested. **End-to-end validation against links with known, independently verified packet loss
is still in progress**, and until it is complete the tool should be read as a structured,
honest instrument rather than a calibrated one. This README deliberately does not quote
benchmark numbers, speed-up figures or accuracy rates, because none have been established yet.

## License

MIT. See [LICENSE](LICENSE).

---

# why-slow（简体中文）

**tcping 告诉你“慢”。`why-slow` 告诉你“为什么慢”。**

`why-slow` 是一个跨平台的网络**诊断**命令行工具。它执行有结构的探测，输出的是**带证据的
结论**，而不只是一个延迟数字。单一静态二进制，零外部依赖，只用标准库。

> 这个工具最早诞生于排查一条**中国大陆 ↔ 美国之间丢包的链路**。CGNAT、IPv6、以及路径中间盒
> 的行为，都是它从第一天起就当作一等公民处理的问题。

## 为什么不直接用 tcping？

[`pouriyajamshidi/tcping`](https://github.com/pouriyajamshidi/tcping) 是一个成熟、维护良好的
工具。它很好地测量 TCP 延迟，用的人也多。如果你的问题只是*“这个 TCP 端口是多少毫秒、稳不稳
定”*，那就应该用它——这件事它比一个新工具做得更好，本项目也没有必要重新实现它。

但是，延迟数字是**测量**，不是**诊断**。像*“平均 23 ms，4% 的探测超过 1000 ms”*这样的总结
只告诉你“确实有问题”，却不告诉你问题究竟是：路径丢包、有状态中间盒、服务器 accept 队列打满，
还是流量其实走了某个 VPN 隧道。这是四种不同的问题，对应四种不同的处理方式，而它们的原始数字
看起来几乎一样。

“慢”之后真正困难的两件事是：

1. **归因**——判断数据到底支持上面哪一种原因；
2. **克制**——不宣称数据支持不了的原因。

`why-slow` 采集的是同一类 TCP 握手时延，但把功夫全部花在**采样之后**的分析上。

| | tcping | why-slow |
|---|---|---|
| 主要输出 | 延迟样本与统计摘要 | 结论、发现项、置信度 |
| 回答的问题 | *有多慢？* | *为什么慢？* |
| 双峰性 | 当作抖动／丢包率报告 | 对照 TCP 重传阶梯做检验 |
| A/B 对比 | 顺序执行，受时序影响 | 交错采样 + 配对符号检验 |
| 路径／出口 | 不检查 | 网卡与 TUN/VPN 归因 |
| NAT | 不检查 | 本地／网关／公网地址对比 |
| 诚实性 | 不适用 | 置信度与严重度分为两个独立维度 |

## 它能发现什么

下面每一项能力，都源于一个“只看延迟数字回答不了”的真实诊断问题。

### 1. 用 TCP 重传阶梯检验双峰延迟

在有丢包的链路上，样本并不是一个向左侧倾斜的抖动分布。而是：少数样本聚集在
`基线 + 1s` 附近，其余样本停留在基线。这个间隔不是随意的，它是一次 TCP 初始重传。初始 RTO
是**量化**的（RFC 6298，它取代了 RFC 2988 的 3 s），因此累积退避阶梯在 Linux 与 Windows 10/11
上是 **1 s / 3 s / 7 s / 15 s**，在较老的 Windows Server 上是 **3 s / 9 s / 21 s**。

这种量化，是仅凭 `connect()` 计时所能获得的最强证据。真正慢的服务器会产生一个**整体偏移或弥散**
的众数；它不会产生一个被钉在 `基线 + 恰好 1.000 s` 上的簇。`why-slow` 先用数据中最大的间隔定位
两个众数的分界，再把这个分界**对照物理阶梯做校验**：只有当高延迟簇落在某个真实阶梯档位上、且足够
紧致（量化）时才会计数。在这个样本量下，盲目聚类会把单个离群点当成一个众数；要求与阶梯对齐，正是
为了防止这一点。

### 2. 交错 A/B 对比与配对符号检验

顺序地比较两个端点（先测完 A，再测完 B）是有误导性的：链路状态在几分钟内就会波动，于是任何“先 A
后 B”的对比都会显示出**属于当时那一刻、而非属于端点**的虚假差异。`why-slow` 采用 **A, B, A, B, …**
的交错采样，并对配对样本做**配对符号检验**，让每一次比较都发生在相同的链路条件下。

> 在一个实际开发案例中，顺序测试得出的结论是“某个端点差了约 3 倍”。改用交错采样重测后，
> **p = 0.42**——两个端点根本没有真实差异。先前的结论纯粹是顺序造成的假象。

### 3. 路径与出口归因

发往目标主机的流量，实际从哪块网卡出去？这块网卡是真实硬件，还是虚拟适配器？如果出口走了 TUN/TAP
设备（WireGuard、OpenVPN、Tailscale、Clash、sing-box、游戏加速器……），那么你测到的延迟描述的可能是
**隧道**，而不是底层链路——这会改变其他所有数字的含义。`why-slow` 按适配器名称做分类，并明确指出它
找到了哪种隧道。

### 4. CGNAT 证据

`why-slow` 会比较本地地址、网关地址，以及外部看到的公网地址。网关落在 `100.64.0.0/10`（RFC 6598）
内，是“运营商也在做 NAT”的一个干净信号，意味着没有中继或打洞就无法接受入站连接。公网 IP 查询会
**刻意绕过系统代理与环境变量代理**：否则一台开着本地代理的机器会把 VPS 的地址当成自己的地址上报，
这不是让诊断变模糊，而是让它**完全颠倒**。

### 5. IPv6 就绪度

**地址存在，不等于 IPv6 能用。** `why-slow` 会检查是否存在**全局单播**地址（`2000::/3`）、是否存在
默认路由，以及它是否真的能承载流量；同时它会给地址标注角色，把 `fe80::` 链路本地、`fc00::/7`
唯一本地、Teredo、6to4 与真正的全局连通性区分开。

## 诚实契约

这是最要紧的部分，所以放在前面说，而不是藏在最后。

`why-slow` 把**置信度（Confidence）**与**严重度（Severity）**作为两个彼此独立的维度输出。一个发现
可以既严重又**不确定**，报告会同时说明两者：

- **严重度**：这个发现对你造成的损害程度——`info`、`notice`、`warning`、`critical`。
- **置信度**：这个工具对结论有多大把握——`low`、`medium`、`high`。

仅凭 `connect()` 计时，**无法证明**某个 SYN 被丢弃了。有状态中间盒、服务器 accept 队列打满
（SYN cookie 处理）、以及服务器软中断（softirq）处理能力不足，都可能产生相似的形状。因此所有结论
都用**“与……相符”（consistent with）**的口径书写——*“时延与一次重传相符”*，而绝不写成
*“SYN 被丢弃了”*——并且把已知的干扰因素与结论一起打印出来。

置信度的标定是刻意为之的：

- `medium`——只占用了一个阶梯档位，但样本量足以分离众数，且分界干净。
- `high`——占用了**两个或更多**阶梯档位，或者同一特征在**相互独立的目标**上复现。两个慢服务器无法
  伪造的量化众数，已接近定论。
- 高延迟样本在时间上**成簇**（游程检验）是**反对**“无记忆丢包”的证据，会把置信度**下调**一级。

如果这种克制读起来像“含糊其辞”，那正是重点。过度宣称的诊断比没有诊断更糟：它会把你引向错误的
修复方向。拒绝夸大是一种特性，也正是 `why-slow` 给出的结论值得被采信的原因。

## 安装

### 使用 Go 工具链

```sh
go install github.com/A015cc/why-slow@latest
```

二进制会安装到 `$(go env GOPATH)/bin`。由于本模块**没有任何外部依赖**，除了模块本身，不需要任何
额外的模块代理。

### 预编译二进制

请从 [GitHub Releases](https://github.com/A015cc/why-slow/releases) 下载。发布包覆盖：

- **Windows**——`why-slow_<version>_windows_amd64.zip`、`..._windows_arm64.zip`
- **macOS**——`..._darwin_amd64.tar.gz`（Intel）、`..._darwin_arm64.tar.gz`（Apple 芯片）
- **Linux**——`..._linux_amd64.tar.gz`、`..._linux_arm64.tar.gz`

每个版本都会附带 `checksums.txt`。二进制以 `CGO_ENABLED=0` 和 `-trimpath` 构建，因此每个都是
单一静态可执行文件——体积小到可以直接 `scp` 到 VPS 上运行，而当你面对的慢的跳数不在手边这台机器
上时，这往往正是你想要的。

## 用法

```
why-slow                          运行全部探测，输出一份汇总报告
why-slow latency <host:port>      握手计时，随后做阶梯／丢包分析
why-slow path <host>              网卡、路由与出口归因
why-slow nat                      本地／网关／公网地址对比
why-slow ipv6                      IPv6 地址、路由与可达性检查
```

示例：

```sh
# 对单个端点采 40 个握手样本
why-slow latency edge.example.net:443 -n 40

# 与第二个端点交错 A/B 采样，并做配对符号检验
why-slow latency a.example.net:443 -n 40 --ab b.example.net:443

# 发往该主机的流量到底从哪里出去？
why-slow path example.net

# 我是否在 CGNAT 后面？
why-slow nat

# 这台机器真的能用 IPv6 吗？
why-slow ipv6

# 一次性运行全部
why-slow
```

全局参数：

| 参数 | 含义 |
|---|---|
| `--json` | 机器可读输出；带版本化的 `schema_version`，便于脚本锁定字段 |
| `--no-color` | 关闭 ANSI 颜色（输出不是 TTY 时同样自动关闭） |
| `--timeout` | 每个探测的超时（默认：拨号 5 s，HTTP 查询 10 s） |
| `--family 4\|6` | 限定只使用某一 IP 协议族 |

### 输出示例

下面这段是输出**格式的示意示例**，并非对任何真实主机的测量，也不是性能基准。

```text
$ why-slow latency edge.example.net:443 -n 40

latency  edge.example.net:443        40/40 completed

  baseline    18.4 ms    IQR 1.1 ms    (n=36)
  cluster   1018.6 ms    IQR 6.2 ms    (n=4)   = baseline + 1000 ms rung

  ladder     modern (RFC 6298: 1/3/7/15 s)  rung 1000 ms occupied
             legacy (3/9/21 s)              no support
  split      clean (nothing stranded between the modes)
  temporal   interspersed (runs z = -0.4)   consistent with memoryless loss
  loss       10.0 %   (95 % Wilson CI 4.0 - 23.1 %)

  VERDICT    [warning] [confidence: medium]
  握手时延呈双峰：少数连接落在基线以上约 1 s，且量化到第一档 TCP 重传阶梯。
  与握手丢包相符，而不是服务器整体变慢。

  confounders named
    - 有状态中间盒或服务器 accept 队列打满也会产生相同形状
    - 若占用两个档位，或该特征在无关目标上复现，置信度将升为 high
```

## 如何解读输出

**阶梯簇才是结论，百分位数只是背景。** 关键不是平均值，而是高延迟众数是否**落在某个阶梯档位上**
（`基线 + 1000 ms`、`+3000 ms`……），以及它是否紧致。落在档位上的紧致簇是一种物理特征；而弥散的
高延迟众数属于拥塞，工具会如实说成拥塞，而不是说成丢包。

**小样本量下的 p95 会被标注。** 在 `n = 40` 时，95 分位是在最高的两个样本之间线性插值得到的，
移动**一个**样本就可能让它摆动几百毫秒。这不是稳定的尾部估计，报告会把它标出来，而不是任由你把它
当成尾部来读。真正想看尾部时，簇和它落在哪一档比重看 p95 更有价值。

**平均值与标准差被有意降级。** 在双峰数据上，平均值落在两个众数**之间的空隙**里，那里根本没有
样本；而标准差被两个众数之间的距离主导，因此两者都描述不了任何一个众数。对上文的分布报告
`平均 118 ms ± 310 ms`，算术上完全正确，诊断上毫无用处。`why-slow` 以基线、簇、以及各自的四分位
距（IQR）为主。

**`confidence: medium` 的含义是：可以据此行动，但先核对干扰因素。** medium 是对“只占用一个档位”
这一事实的诚实读数。它说的是*“形状与一次重传相符，并且本次运行中没有任何东西与它相矛盾”*——它
并没有说原因已被证明。在升级处理之前，请先检查报告列出的干扰因素；提升置信度最快的办法，就是拿
同一个探测去测一个**无关目标**，看同样的特征是否复现。

## 它无法告诉你什么

一份诊断的价值，取决于它有没有说清自己的边界。

- **单台主机无法断定是否处于 CGNAT。** `why-slow` 运行在你的机器上，而你家路由器的 WAN 地址
  从这里根本看不到。内网看到私有地址或运营商级地址，是“存在 NAT”的有力证据，但要把**本地 NAT**
  与**运营商 CGNAT** 区分开，往往需要来自外部或第二个观测点的视角。工具只报告它能看到的东西，
  在无法支撑的结论前停下。
- **被截断的拨号超时不是一个“很慢的样本”。** 撞上超时的探测是一次**被截断**的测量，而不是一个
  `>5 s` 的延迟。把它喂进分析，会凭空制造出阶梯检验本来要找的那个高延迟众数，因此“完成的测量”
  与“超时”被严格分开处理。
- **单一观测点无法分离中间盒时延与服务器时延。** 从一个观测点看，“SYN 被延迟了”与“服务器接受
  得慢”长得一模一样。要分离二者，需要第二个观测点，或在一端抓包。`why-slow` 的做法是把中间盒
  行为列为干扰因素，而不是去猜。
- **它是一把握手尺。** 它量的是连接建立，不是吞吐、不是应用层延迟、也不是完整传输。一条链路完全
  可能握手干净、吞吐糟糕，而本工具看不到后者。
- **`connect()` 计时，决定了任何结论能宣称的上限。** 以上所有限制，都源自这一句话。

## 状态

统计层（簇检测、阶梯检验、Wilson 区间、游程检验）已有单元测试覆盖。**针对“已知且经独立验证的
丢包链路”的端到端验证仍在进行中**；在完成之前，本工具应被理解为一个有结构、诚实的仪器，而不是
一个已经完成标定的仪器。本 README 刻意不引用任何基准数字、提速倍数或准确率，因为目前这些都还
没有建立起来。

## 许可证

MIT，详见 [LICENSE](LICENSE)。
