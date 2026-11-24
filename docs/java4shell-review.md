# Java4Shell / CVE-2026-114938 防守核验

资料核对时间：2026-11-24（Asia/Shanghai）。本项目只实现无害识别和本地主机证据采集，不包含漏洞触发器、畸形 Base64、内存破坏验证、泄露或命令执行代码。

## 已核实事实

- Oracle 是 CVE 分配方。官方记录将问题归入 Java SE `Compiler`，CVSS 3.1 为 8.1（AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H），说明攻击者可经多种协议向相关 API 提供数据；成功利用可能接管受影响产品。
- CISA ADP 将弱点标为 CWE-122，并在 2026-11-17 记录 `Exploitation: none`、`Automatable: no`、`Technical Impact: total`。这表示当时无已知利用证据，不表示以后不会变化。
- Calif 披露与 OpenJDK 修复提交将根因定位到 HotSpot x86-64 AVX-512 Base64 intrinsic 的短尾处理。修复提交 `5177a70b385c16f26ede191fdac7aaba0bed0f8b` 把短于完整 Base64 块的尾部转交标量路径。
- 公开首个修复版本为 17.0.21.1、21.0.13.1、25.0.5.1、27.0.1.1。公开研究给出的通用受影响起点为 17.0.6；18 及之后的非支持版本应升级到受支持修复线。Oracle Java SE 8u511b33-perf 是官方列出的特殊受影响构建，不能据此扩大到所有 Java 8；通用 `java -version` 输出不能可靠区分该 perf 构建，因此程序要求用 Oracle 资产/补丁库存单独核验。
- 披露路径要求 HotSpot/GraalVM 类 VM、x86-64、当前 JVM 可见相应 AVX-512/BMI2 能力、Base64 intrinsic 和 JIT 路径。OpenJ9/J9 不使用该 HotSpot intrinsic。硬件与运行参数是适用条件，不是版本补丁的替代品。

标准 Java 8 构建需要与 Oracle Java SE Performance Pack 分开判定。Oracle 的 CVE 清单在 Java 8 线仅列出 8u511b33-perf。已识别的 Red Hat、Debian、Ubuntu、Temurin、Corretto 和 Azul 标准 OpenJDK 8 构建按披露范围排除，缺少明确厂商或产品证据的构建保持未知。Oracle 8u511 的短标识仍需核对具体发行构建。
[Oracle CVE 记录](https://www.cve.org/CVERecord?id=CVE-2026-114938) · [Red Hat 公告](https://access.redhat.com/security/cve/CVE-2026-114938) · [Azul 安全更新](https://www.azul.com/products/security-update/)

## 程序如何判断

远程扫描只复用已经取得的响应，识别 Java 产品特征并输出 `java_product_hint`。它不会为 Java4Shell 增加请求，也不会尝试寻找或调用产品接口。网页证据无法获知 JVM 和 CPU，因此永远不会直接生成“漏洞已确认”。

本地主机采集：

```bash
bash scripts/x2shell-check.sh --java4shell --json
x2shell-check collect --java-command
```

- Linux 读取当前可见的 `/proc/PID/maps`，按实际映射的 `libjvm.so` 与磁盘文件关联。设备号、inode、进程身份和映射在采集中复核。已删除、身份不明或中途变动的映射保留待复核。
- Bash 按逻辑 CPU 读取四项 flags，Rust 交叉核对 CPUID 和 `/proc/cpuinfo`。盘点通过 `release` 读取 JDK 厂商与完整构建。Linux 额外发现当前账号的 SDKMAN 和 Gradle JDK。使用自定义目录的 Maven 工具链和 CI 缓存可通过 Bash `--root` 或 Rust `--java-root` 补查。
- 运行参数可用 Bash `--jcmd` 或 Rust `--java-attach` 显式读取 `VM.version` 和 `VM.flags -all`。附加可能启动诊断监听器或造成短暂停顿。默认采集不执行 Java，也不读取目标进程环境。显式信任启动参数时，报告区分估算和 jcmd 实测。
- `--java-path` 可查询指定启动器的版本。配合 `--java-default-flags` 才会另外启动 JVM，对照默认值、命令行关闭、受控 `JAVA_TOOL_OPTIONS` 关闭的值与来源。启动前清除采集器继承的 Java 选项变量。对照只写入 `launcher_flag_probe`，运行中 JVM 的裁决仍依据实际进程证据。

未启动的镜像需要挂载后通过明确目录盘点，或在容器内运行采集器。宿主机的包数据库只用于同根目录、同挂载命名空间且映射身份已核实的运行进程。工作负载迁移后需重新核对客户机 CPU。

## 发行版软件包证据

Linux 默认按实际 `libjvm.so` 查已安装软件包，支持 DEB、RPM 和 APK。基线按发行版、分支和源包匹配，再使用包管理器的原生版本比较。单次巡检最多尝试 12 个不同库路径，软件包子步骤共用 8 秒预算。未匹配到公告时保留包信息和未知补丁状态。

`package_evidence.patch_status` 是软件包版本与厂商参考的比较结果。只有包版本达到对应基线，并且 `release_build_matches` 为真，才可能将缺少构建裁决的资产认定为达到修复参考。运行进程还要求映射身份可靠且运行自报与磁盘构建一致。此证据来自本机软件包数据库，未校验软件包签名或逐字节核验库文件。

显式 `--java-package-details` 在 Debian/Ubuntu 增加本机 APT 缓存中的候选版本和可读取的压缩 changelog 线索。缓存查询不更新索引。没有 changelog 命中不影响公告判定。RPM 和 Alpine 的修复参考来自维护的厂商公告或发行版仓库元数据。

| 运行态状态 | 含义 |
| --- | --- |
| `affected` | 受影响构建、适用的 CPU 和未缓解运行参数均有证据 |
| `mitigated` | 适用的运行进程具有明确的缓解参数证据 |
| `not_affected` | 构建、VM 或 CPU 可排除当前适用性 |
| `potential` | 安装或运行证据提示需复核 |
| `unknown` | 关键证据缺失或冲突 |

## 处置顺序

优先升级到产品或 JDK 厂商明确提供的固定构建，重建容器并重启全部 JVM。不能立即升级时，厂商/研究建议使用 `-XX:-UseBASE64Intrinsics`；x86-64 可用 `-XX:UseAVX=2` 作为更宽的临时缓解。参数必须在运行服务上生效并验证，不能把配置文件存在当成实际生效。ARM JVM 可能拒绝 x86 专用参数，因此跨架构共享配置前必须测试。

## 来源

- [Debian 安全跟踪器](https://security-tracker.debian.org/tracker/CVE-2026-114938)、[Ubuntu CVE](https://ubuntu.com/security/CVE-2026-114938)、[Alpine 安全数据库](https://security.alpinelinux.org/vuln/CVE-2026-114938)。
- [Red Hat 公告](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018)、[Rocky Linux 安全公告](https://errata.rockylinux.org/)、[AlmaLinux 公告](https://errata.almalinux.org/10/ALSA-2026-100568.html)、[Amazon Linux CVE](https://explore.alas.aws.amazon.com/CVE-2026-114938.html)。
- [Rocky Linux 中文社区排查流程](https://www.rockylinux.cn/notes/java4shell-cve-2026-114938-find-patch-jvm.html)。
- [Oracle CVE 记录](https://www.cve.org/CVERecord?id=CVE-2026-114938)，发布时间 2026-11-17。
- [Oracle November 2026 Critical Security Patch Update](https://www.oracle.com/security-alerts/cspunov2026.html)。
- [OpenJDK 修复提交 5177a70b385c](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b)。
- [Calif Java4Shell 技术披露](https://calif.io/java4shell)。
- [JFrog 受影响与修复版本整理](https://research.jfrog.com/post/java4shell-vulnerability/)。
- [Semgrep 防守核验建议](https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability/)。
- [ikow/java4shell-poc](https://github.com/ikow/java4shell-poc) 固定阅读提交 `15904ba6cf099e106d049162901e8a2e063bf3bf`，仅参考其分析和无害扫描判据，未运行或复制 exploit/PoC。

社区资料用于补充根因与适用条件；版本与供应商状态仍应以最新官方公告为准。
