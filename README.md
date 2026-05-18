# zwh_light_emerge_collect v8.0 — Linux 应急响应一键取证脚本

## 概述

面向攻防演练防守方的 **单机一键取证工具**。在失陷主机上运行，约 1-3 分钟完成系统全维度证据固定，输出结构化目录 + tar.gz 打包，附带风险评分和 AI 可消费的 JSON 关联图谱。

**核心设计理念：** 单人防守、快速固定、机读优先（Key-Value 摘要 + JSON + 统一时间线），让接收方 30 秒内判断是否失陷，再按需深入各子报告。

## 版本演进

| 版本 | 主要变化 |
|------|----------|
| v8.0 | 网络层2/3取证(ARP/DNS/Promiscuous)、隐藏内核模块检测、sysctl/sysrq/auditd 深度内核检查、Ptrace检测、轮转日志全面采集、用户登录取证、容器深度取证+K8s检测、eBPF程序深度检测、风险评分引擎、Entity Correlation图、Shell历史智能分类、SSH横向移动图谱、自定义输出目录、全量模式、纯文本输出 |
| v7.0 | Bash 3.x 兼容、快速模式、容器逃逸检测增强、证据校验文件、IOC 驱动全量搜索、Java 应用服务器目录取证、GeneratedMethodAccessor 内存马检测 |

## 快速开始

```bash
# 基本用法（默认输出到 /tmp）
sudo bash zwh_light_emerge_collect_v8.0.sh

# 指定输出目录
sudo bash zwh_light_emerge_collect_v8.0.sh -o /evidence/collect

# 全量模式（含内存 dump，文件更大但更深入）
sudo bash zwh_light_emerge_collect_v8.0.sh --full

# 快速模式（跳过 WebShell 深度扫描、大日志、文件哈希）
sudo bash zwh_light_emerge_collect_v8.0.sh --quick

# 携带 IOC 文件（自动全量命中扫描）
sudo bash zwh_light_emerge_collect_v8.0.sh /path/to/ioc.txt

# 通过环境变量传入 IOC
export IOC_FILE=/path/to/ioc.txt && sudo bash zwh_light_emerge_collect_v8.0.sh
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `--quick`, `-q` | 快速模式，跳过深度扫描（WebShell 全量、>200MB 日志、文件哈希） |
| `--full`, `-f` | 全量模式，启用内存 dump 和深度 ELF 分析 |
| `--output-dir`, `-o <dir>` | 自定义输出目录（默认 `/tmp`） |
| `--no-color` | 纯文本输出，禁用颜色 |
| `--help`, `-h` | 显示帮助 |
| `[IOC_FILE]` | IOC 文件路径（每行一个 IP/域名/哈希，支持 `#` 注释） |

## 运行要求

- **权限：** root（sudo）
- **Shell：** Bash 4.0+（3.x 可运行但部分功能降级，建议升级）
- **操作系统：** CentOS 7/8、RHEL 7/8/9、Ubuntu 16.04+、Debian 9+、OpenCloudOS 等
- **CPU 限制：** 脚本总 CPU 时间 300 秒（`ulimit -t 300`）
- **预计耗时：** 1-3 分钟（取决于日志量和是否有 Java 进程）
- **磁盘占用：** 通常 50-500MB（取决于日志大小，单日志上限 500MB）
- **依赖工具：** 均为系统自带（ps/netstat/lsmod/find/tar 等），部分增强功能需要 jcmd/jps/lsof/bpftool

## 输出结构

取证完成后生成 `emergency_<主机名>_<时间戳>.tar.gz`，解压后目录结构：

```
emergency_20260518_143052/
├── summary.txt                  # [关键] Key-Value 摘要，30秒判断失陷
├── summary.json                 # [关键] 结构化摘要，供自动化平台消费
├── risk.json                    # [关键] 风险评分引擎（CRITICAL/HIGH/MEDIUM/LOW）
├── timeline.txt                 # 采集起止时间
├── timeline_master.txt          # 统一时间线（所有事件按时间戳排序）
├── evidence_hashes.txt          # 证据文件 SHA256 校验
├── process_graph.json           # 进程父子关系图（PID/PPID/User/Network/Risk）
├── sockets.json                 # 结构化网络连接 JSON
├── entity_correlation.json      # 实体关联图（PID↔IP↔File↔User）
├── ioc_output.json              # 自动提取的 IOC（IP/域名/哈希/URL）
├── ioc_sweep.txt                # IOC 全量命中扫描结果
├── log_collection.txt           # 日志采集清单
│
├── system_info.txt              # 系统基础信息 + 可信基线
├── process.txt                  # 进程快照 + 隐藏进程检测
├── proc_snapshot.txt            # /proc/PID 完整快照 + 已删除文件检测
├── network.txt                  # 网络连接 + 防火墙 + DNS + 路由 + 流摘要
├── crontab.txt                  # 持久化机制（cron/systemd/SSH/自启动/勒索信）
├── history_cmds.txt             # 历史命令 + 可疑模式检测
├── webshell_scan.txt            # WebShell 11维深度扫描
├── memshell_check.txt           # 内存马检测（Java/PHP/Python/Node.js/eBPF）
├── tomcat_forensics.txt         # Java 应用服务器目录取证
├── log_pattern_analysis.txt     # 应用日志可疑模式分析
├── temp_class_check.txt         # 临时目录 Java class 文件检测
│
├── logs/                        # 日志采集（含轮转日志 .1/.gz/date-based）
├── extra/                       # 扩展取证数据
│   ├── recent_files.txt         # 最近3天文件变更
│   ├── file_hashes.txt          # 关键二进制 + 账户文件 SHA256
│   ├── suid_sgid.txt            # SUID/SGID 异常文件
│   ├── kernel_rootkit.txt       # 内核模块 + Rootkit 特征
│   ├── kernel_deep.txt          # 深度内核检查（隐藏模块/sysctl/sysrq/auditd）
│   ├── ptrace_raw_sockets.txt   # Ptrace + Raw Socket 检测
│   ├── memfd_preload.txt        # memfd_create 无文件执行 + LD_PRELOAD 劫持
│   ├── net_l2_l3.txt            # ARP/DNS/hosts/Promiscuous/IPv6
│   ├── login_forensics.txt      # 用户登录取证（wtmp/btmp/lastlog）
│   ├── operation_traces.txt     # 操作痕迹（SSH known_hosts/GUI/Vim/数据库历史）
│   ├── shell_classification.txt # Shell 历史智能分类
│   ├── lateral_movement.txt     # SSH 横向移动图谱
│   ├── ssh_persistence.txt      # SSH 持久化与后门检测
│   ├── filesystem_protection.txt# 不可变文件 + MIME 劫持检测
│   ├── forensic_enhancement.txt # 文件系统元数据 + 软件包时间线
│   ├── container_check.txt      # 容器环境检测（含逃逸风险）
│   ├── namespace_container.txt  # Namespace 隔离 + 容器深度取证 + K8s
│   ├── ebpf_deep.txt            # eBPF 程序/Map/挂载点深度检测
│   ├── audit_logs.txt           # 审计日志（auditd + journald）
│   └── system_limits.txt        # 系统资源限制（ulimit + sysctl）
```

## 采集内容详解

### 1. 系统基础信息 (`system_info.txt`)
- 主机名、OS 版本、内核版本
- CPU/内存/磁盘/分区
- 时区、系统安装日期估算、运行时间
- 登录用户、最近登录(20条)、失败登录(20条)
- 用户列表 + UID=0 特权用户标记
- 内核模块列表（lsmod）
- 挂载信息、磁盘使用
- 环境变量（敏感字段 PASS/SECRET/KEY/TOKEN 自动脱敏）
- **可信基线：** RPM 包校验 (`rpm -Va`)、DEB 包校验 (`debsums`)、SELinux/AppArmor/ASLR 状态

### 2. 进程信息 (`process.txt` + `proc_snapshot.txt`)
- 进程快照（ps aux 按 CPU 排序前500）
- 进程树（pstree）
- **隐藏进程检测：** 对比 `/proc` 目录和 `ps` 输出，发现差异即告警并 dump 详情
- Java/中间件进程 `/proc/PID` 完整快照：
  - environ（敏感变量过滤 + 完整保存到独立文件）
  - cwd（工作目录）
  - limits（文件描述符限制）
  - maps 中 JAR 映射（标记 `/tmp`、`/dev/shm` 等**高危路径**）
  - 可写可执行内存段（rwxp）检测
- **已删除文件检测：** lsof +L1 + /proc/PID/fd 中 `(deleted)` 标记

### 3. 网络连接 (`network.txt` + `extra/net_l2_l3.txt`)
- ss/netstat/lsof 网络连接
- `/proc/net` 原始数据（tcp/udp/tcp6/udp6）
- 防火墙规则（iptables + iptables NAT + nftables + firewalld）
- 路由表 + ARP 表
- DNS 配置（`/etc/resolv.conf` + `/etc/hosts`）
- TCP Wrappers（hosts.allow/hosts.deny）
- Sudoers 配置 + PAM 模块检查
- **网络连接流摘要：** 按目标 IP 统计 ESTABLISHED 连接数
- **网卡混杂模式检测：** 可能为抓包行为
- IPv6 邻居表 + 路由表 + 活动服务绑定

### 4. 持久化机制 (`crontab.txt`)
- 系统 crontab + `/etc/cron.d/` + 所有用户 crontab
- systemd timers + 已启用 services + socket 单元
- **可疑 systemd 服务：** ExecStart 指向 `/tmp`、`/dev/shm` 等路径
- rc.local + `/etc/profile.d/`（标记 curl/wget/base64 等可疑命令）
- SSH 配置审计（PermitRootLogin/ProxyCommand/ForceCommand 检测）
- authorized_keys（command= 限制检测）
- **XDG 自启动目录检查**
- **勒索信检测：** 扫描常见勒索信文件名模式

### 5. 操作痕迹 (`extra/login_forensics.txt` + `extra/operation_traces.txt`)
- 成功登录记录（wtmp）+ 失败登录记录（btmp）
- 每个用户最后登录时间（lastlog）
- auth.log/secure 最近登录事件
- 当前登录会话（who -a）+ utmpdump
- **SSH known_hosts：** 横向移动关键证据
- GUI 最近文件（recently-used.xbel）
- Vim 痕迹（.viminfo）
- 数据库历史（.mysql_history / .psql_history）

### 6. 历史命令 (`history_cmds.txt` + `extra/shell_classification.txt`)
- 所有用户 `.bash_history` 最后1000条
- 可疑命令模式检测（curl/wget/nc/bash -i/python -c/base64 -d/chmod 777）
- **智能分类：** 下载执行 / 提权 / 痕迹清理 / 横向移动 / 信息收集 / 持久化

### 7. WebShell 扫描 (`webshell_scan.txt`) — 11维检测
1. 最近30天修改的脚本文件
2. 高危函数特征（eval/system/exec/Runtime.exec/ProcessBuilder 等）
3. **管理工具特征：** 菜刀/蚁剑/冰蝎/哥斯拉/Weevely/C99/R57
4. 经典特征库匹配（含框架白名单自动排除）
5. **图片马检测：** 图片中嵌入 PHP/JSP/ASP 代码 + 双扩展名
6. **配置型后门：** .htaccess / .user.ini / web.config
7. **文件熵分析：** 熵 > 7.0 告警（高度随机 = 可能加密）
8. 异常文件大小（<50B 极小 loader / >500KB 打包 WebShell）
9. 可疑文件名（纯数字 / 随机字符串命名）
10. 时间戳异常（ctime 与 mtime 差异 >30天）
11. 隐藏脚本文件（`.` 开头）

### 8. 内存马检测 (`memshell_check.txt`) — 多语言覆盖
**Java：**
- jps 进程列表 + Java Agent 参数检测
- JVM 系统属性 + 启动标志
- 完整类加载器 dump
- 可疑类检测（Filter/Servlet/Listener/Shell/Cmd/Memshell/Inject 等）
- **GeneratedMethodAccessor 计数：** >25000 告警，>18000 可疑
- 动态注入类检测（来源 `[?:?]` 的类 — 内存马典型特征）
- 线程信息 + JIT 编译信息
- 内存映射 JAR 分析（标记非标准路径和高危路径）
- `/proc/PID/fd` 完整 JAR/WAR 文件分析

**PHP：**
- PHP 配置检查（auto_prepend_file/disable_functions/open_basedir）
- PHP-FPM 配置审计
- PHP 进程命令行 + 环境变量扫描
- LD_PRELOAD 劫持检测

**Python：**
- Python/Flask/Django/Gunicorn 进程检测
- sitecustomize / usercustomize / .pth 持久化检测

**Node.js：**
- 进程检测 + NODE_OPTIONS/NODE_PATH 环境变量审计

**eBPF：**
- bpftool 程序列表 + 可疑类型检测（kprobe/tracepoint/xdp）

### 9. Java 应用服务器目录取证 (`tomcat_forensics.txt`)
- **自动发现：** 进程命令行提取 + 常见路径扫描，支持 Tomcat/Jetty/WildFly/WebLogic/WebSphere
- webapps 目录（近期 WAR/JSP/非标准名册）
- lib 目录（近期修改 JAR + **Agent Manifest 检测**）
- conf/server.xml（Valve/Filter/Pipeline + **非标准 Valve 告警**）
- conf/web.xml（Filter/Servlet/Listener 注册 + **内存马特征名直接匹配**）
- bin 目录（setenv.sh/catalina.sh 中 javaagent/agentpath 注入检测）
- work/Catalina（近期编译 JSP 源文件 + 晚于 server.xml 的 class）
- logs（catalina.out + localhost_access_log + host-manager/manager 日志）
- context.xml（数据库凭证泄露检测）

### 10. 内核与 Rootkit 检测 (`extra/kernel_*.txt`)
- 加载的内核模块 + 模块签名状态
- **隐藏内核模块检测：** `/proc/modules` vs `lsmod` 交叉对比
- 未签名模块标记
- `/etc/ld.so.preload` 检查
- core_pattern 检查
- **Rootkit 字符串探测：** hidepid/diamorphine/adore/kbeast/suterusu
- Capabilities 审计（cap_setuid/cap_sys_admin/cap_sys_ptrace/cap_net_raw）
- sysctl 内核参数完整 dump
- Magic SysRq 状态检查
- auditd 审计规则 + 服务状态
- 内核启动参数 + LSM 状态

### 11. 进程安全检测 (`extra/ptrace_raw_sockets.txt` + `extra/memfd_preload.txt`)
- **Ptrace 检测：** 遍历所有进程 TracerPid，发现被调试进程即告警
- Raw Socket 进程检测（`/proc/net/raw`）
- Packet Socket 进程检测（`/proc/net/packet`）
- **memfd_create 无文件执行检测：** 含白名单排除（pipewire/pulseaudio 等正常行为）
- 已删除二进制运行检测
- 进程级 LD_PRELOAD 检查
- 非标准路径 .so 加载检测

### 12. 容器检测 (`extra/container_check.txt` + `extra/namespace_container.txt`)
- 容器环境判断（cgroup/docker.sock/.dockerenv）
- Docker/containerd/kubectl 状态
- **容器逃逸风险：** docker.sock 挂载/特权模式/Seccomp 禁用
- Namespace 列表 + 关键进程 Namespace 对比
- **特权容器详细检测：** Privileged/hostNetwork/hostPid/docker.sock 挂载/敏感路径挂载
- Kubernetes 检测：kubeconfig/ServiceAccount Token/kubectl 上下文
- Container Runtime Socket 枚举

### 13. eBPF 深度检测 (`extra/ebpf_deep.txt`)
- eBPF 程序列表 + Map 列表
- 程序附加点分析
- 可疑 eBPF 程序类型标记（kprobe/tracepoint/xdp/tc/socket_filter）
- BPF 文件系统挂载状态
- unprivileged_bpf_disabled / bpf_jit_enable 状态

### 14. 文件系统保护 (`extra/filesystem_protection.txt`)
- **不可变文件检测：** lsattr 扫描 `/tmp`、`/dev/shm`、`/var/tmp`、`/etc`、`/root`、`/home` 中的 `chattr +i` 文件
- **MIME type 劫持：** .desktop 文件 Exec 指向可疑路径
- xdg-mime 默认浏览器/终端配置

## 关键特性

### 风险评分引擎 (`risk.json`)

自动对取证结果进行四档评分：

| 等级 | 分数范围 | 示例 |
|------|---------|------|
| CRITICAL | ≥300 | memfd_create 无文件执行、隐藏内核模块、/etc/ld.so.preload 劫持、Ptrace 追踪 |
| HIGH | 150-299 | WebShell 特征命中、内存马 GeneratedMethodAccessor 异常、高危路径 JAR、反向Shell |
| MEDIUM | 50-149 | 大量 ESTABLISHED 连接、大量未知来源类、未签名内核模块、SSH 后门 |
| LOW | <50 | 高熵值文件、时间戳异常、隐藏脚本 |

每项发现均标注来源文件和详细描述，可直接作为应急报告证据。

### IOC 驱动全量扫描

- 支持从文件或环境变量加载 IOC（IP/域名/哈希，每行一个，支持 `#` 注释）
- 在所有已采集数据中自动搜索，跳过二进制文件
- 输出命中/未命中结果
- 同时支持 **IOC 自动提取**（`ioc_output.json`）：从采集数据中自动识别外网 IP（排除内网）、域名、SHA256、URL

### 智能分析

- **Shell 历史智能分类：** 下载执行 / 提权 / 痕迹清理 / 横向移动 / 信息收集 / 持久化
- **SSH 横向移动图谱：** known_hosts + auth.log + shell 历史 + SSH config 交叉关联
- **Entity Correlation 图：** PID↔IP↔File↔User 关系 JSON，可直接导入图数据库
- **Process Graph：** 所有进程的 pid/ppid/user/cmdline/cwd/network/risk_tags 结构化数据
- **应用日志模式分析：** 认证异常 / 异常堆栈 / 内存马特征 / 会话异常 / 外联命令执行

## 安全保护机制

- **防重入：** flock 锁文件，防止并发运行
- **性能限制：** CPU 300秒上限、find maxdepth 8、日志单文件 500MB 上限
- **安全超时：** 所有外部命令通过 `safe_run()` 包装，避免卡死
- **框架白名单：** WebShell 扫描自动排除 ThinkPHP/Laravel/Yii/WordPress 等框架路径
- **敏感信息脱敏：** 环境变量中 PASS/SECRET/KEY/TOKEN 自动打码
- **临时文件清理：** trap EXIT 自动清理
- **降级兼容：** tar --warning / mapfile / EPOCHREALTIME / pipefail 均提供 Bash 3.x 回退

## 使用场景

1. **攻防演练防守方：** 发现告警后第一时间固定证据，防止攻击者清痕
2. **安全事件应急响应：** 快速获取失陷主机全貌，判断攻击路径和影响范围
3. **定期安全巡检：** 结合 cron 定时运行，对比基线发现异常变更
4. **自动化 SOC 对接：** summary.json + risk.json 可直接被 SIEM/SOAR 平台消费

## 示例

```bash
# 场景1：收到 EDR 告警，某服务器可疑出站连接
sudo bash zwh_light_emerge_collect_v8.0.sh -o /evidence/case_001

# 场景2：有已知恶意 IP/域名清单，快速全量命中扫描
cat > /tmp/ioc.txt << 'EOF'
45.79.207.181
72.14.178.148
malicious-c2.example.com
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
EOF
sudo bash zwh_light_emerge_collect_v8.0.sh /tmp/ioc.txt

# 场景3：服务器负载高，跳过深度扫描
sudo bash zwh_light_emerge_collect_v8.0.sh --quick -o /evidence/quick_check

# 场景4：疑似内存马，启用全量模式（含内存 dump）
sudo bash zwh_light_emerge_collect_v8.0.sh --full -o /evidence/memshell_case
```

## 结果判读速查

拿到 `summary.txt` 后，30秒快速判断：

```
重点看这些指标是否 >0：

memshell_GeneratedMethodAccessor_high     → 内存马高危
memshell_javaAgent                        → Java Agent 注入
webshell_detected                         → WebShell 命中
deletedFiles_highRisk                     → 已删除文件仍在运行
hiddenProcess                             → 隐藏进程
persistence_suspicious                    → 可疑持久化
hiddenKmod                                → 隐藏内核模块
ptraceDetected                            → 进程被调试
```

## 注意事项

1. **必须 root 执行** — 大量操作需要读取 `/proc`、内核模块、网络连接等
2. **对业务几乎无影响** — 仅读取系统文件和 `/proc`，不修改任何配置
3. **磁盘空间要求低** — 通常 50-500MB，大日志文件自动截取头尾各 50MB
4. **打包文件可能较大** — 建议通过 scp 或 U 盘传出，不要在失陷主机长期留存
5. **jcmd/jps 未安装时** — Java 内存马检测部分跳过，建议提前安装 `java-*-openjdk-devel`
6. **部分功能依赖可选工具** — lsof、bpftool、ausearch、journalctl，缺失时自动跳过对应检测项
7. **取证结果具有时效性** — 内存马可能因进程重启而消失，建议发现告警后立即执行
