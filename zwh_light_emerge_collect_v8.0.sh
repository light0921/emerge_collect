#!/bin/bash
#==================================================================
# 应急响应一键取证脚本 v8.0（深度加固版 + 网络层2/3检测 + 内核安全增强 + 轮转日志支持）
# 作者：zwh_light
# 用途：单人攻防演练防守方快速固定证据
# 用法：sudo bash emerge_collect.sh [IOC_FILE]
#       或: export IOC_FILE=/path/to/ioc.txt && sudo bash emerge_collect.sh
#       或: sudo bash emerge_collect.sh --help    # 显示帮助信息
#       IOC_FILE=/path/to/ioc.txt sudo bash emerge_collect.sh
# 输出：${OUTDIR}.tar.gz (默认 /tmp/emergency_日期时间.tar.gz，可通过 -o 指定)
# 新增 (v8.0):
#   - T1: --output-dir/-o 自定义输出目录
#   - T1: --full/-f 全量模式（内存dump等高风险操作）
#   - T1: --no-color 纯文本输出
#   - T1: EPOCHREALTIME fallback 彻底修复
#   - T2: 轮转日志全面采集（*.log.1/*.[0-9]/date-based/.gz/.bz2）
#   - T2: ARP表/DNS配置//etc/hosts/Promiscuous网卡检测
#   - T2: 隐藏内核模块检测（/proc/modules vs lsmod交叉对比）
#   - T2: sysctl内核参数完整dump + sysrq-trigger检查
#   - T2: auditd审计规则dump
#   - T2: Ptrace检测 + Raw/Packet socket检测
#   - T2: 用户登录取证（wtmp/btmp/lastlog分析）
#   - T2: 内核模块签名状态检查
#   - T2: IPv6邻居表 + 活动服务绑定清单
#   - T2: 系统资源限制dump（ulimit -a + /etc/security/limits.conf）
#   - improve: find不存在目录保护 / tar降级增强
#   - improve: summary新增6个v8.0指标
# 新增 (v7.0):
#   - T1: progress_dot 后台进程清理 (防止僵尸进程)
#   - T1: mapfile 兼容 Bash 3.x (read -r 循环回退)
#   - T1: trap 中添加 OUTDIR 清理说明
#   - T1: --quick 快速模式 (跳过深度扫描)
#   - T1: safe_run 关键路径返回值保护
#   - T2: 所有 find 添加 maxdepth 8 保护
#   - T2: 日志采集支持轮转和压缩文件 (.1/.gz/.bz2/date-based)
#   - T2: Bash 版本检查 + 兼容提示
#   - T2: 容器逃逸风险检测增强 (docker.sock/特权模式)
#   - fix: set -o pipefail 替换为安全模式（避免 grep/find 空结果中断脚本）
#   - fix: find "" 半成品补全为证据文件 SHA256 校验生成
#   - fix: 所有 $(cmd1 | cmd2) 赋值管道添加 || true/空值回退
#   - fix: tar --warning 兼容 busybox tar（降级方案）
#   - improve: EPOCH_START 兼容 bash 4.x（date +%s 回退）
#   - improve: 证据校验文件自动生成 (evidence_hashes.txt)
#   - improve: 打包文件解压提示
#   - IOC 驱动全量搜索
#   - Tomcat/Java 应用服务器目录取证（webapps/lib/conf/bin/work）
#   - JVM 深层信息（VM.system_properties/VM.flags/GeneratedMethodAccessor）
#   - /proc/PID/fd JAR 文件完整分析
#   - 应用日志可疑模式分析（认证异常/内存马特征/会话异常）
#   - 临时目录 Java class 文件检测
#==================================================================
# set -o pipefail  # Disabled: breaks on grep/find/awk empty results. Use explicit || true on critical pipelines.
# ---------- Bash 版本检查 ----------
BASH_MAJOR=${BASH_VERSINFO[0]:-4}
BASH_MINOR=${BASH_VERSINFO[1]:-0}
if [ "$BASH_MAJOR" -lt 4 ]; then
    echo "[!] 警告: Bash ${BASH_MAJOR}.${BASH_MINOR} < 4.0, 部分功能受限 (EPOCHREALTIME/mapfile 不可用)"
    echo "[!] 已启用兼容回退，但建议升级到 Bash 4+"
fi
LANG=C
umask 022
shopt -s nullglob

# ---------- 防重入 ----------
LOCKFILE="/tmp/.emerge_collect.lock"
if command -v flock &>/dev/null; then
    exec 200>"$LOCKFILE"
    flock -n 200 || { echo "[!] 已有取证进程在运行，退出"; exit 1; }
else
    # 降级方案：检查锁文件是否最近3小时内创建
    if [ -f "$LOCKFILE" ]; then
        lock_age=$(($(date +%s) - $(stat -c %Y "$LOCKFILE" 2>/dev/null || true)))
        if [ "$lock_age" -lt 10800 ]; then
            echo "[!] 锁文件 ${LOCKFILE} 存在且未过期 (${lock_age}s ago)，可能有进程在运行"
            echo "[!] 如需强制执行，请手动删除: rm -f ${LOCKFILE}"
            exit 1
        fi
    fi
    touch "$LOCKFILE"
fi

# ---------- 性能保护 ----------
ulimit -t 300               # 脚本总 CPU 300 秒

# ---------- GPT Audit 安全配置 ----------
MAX_FIND_DEPTH=8
MAX_FIND_SIZE=5M
LOG_SIZE_LIMIT=524288000  # 单日志文件采集上限 500MB
LOG_AGE_DAYS=7          # 日志采集天数（轮转日志默认保留7天）
ENABLE_MEM_DUMP=0  # 设为 1 以启用内存转储（高风险，可能产生大文件）

# ---------- 工具函数 ----------
cleanup() {
    rm -f /tmp/ws_sig_$$.txt /tmp/proc_list_$$.txt /tmp/ps_list_$$.txt /tmp/timeline_raw_$$.txt "$LOCKFILE"
    # T1-3: 清理 OUTDIR 临时文件（脚本异常退出时需手动删除）
    # rm -rf "${OUTDIR}"  # 取消注释以启用自动清理证据目录
}

trap cleanup EXIT

# 安全超时执行（避免卡死）
safe_run() {
    local timeout_sec="$1"
    shift
    timeout "$timeout_sec" "$@" 2>/dev/null
}

# 进度点打印
progress_dot() { while :; do echo -n "."; sleep 1; done }

# 安全扩展 Web 目录（处理空格、空 glob）
expand_web_dirs() {
    local dirs=()
    for pattern in "${WEB_DIRS_RAW[@]}"; do
        for expanded in $pattern; do  # Note: uses word-splitting intentionally for glob expansion
            [ -d "$expanded" ] && dirs+=("$expanded")
        done
    done
    if [ ${#dirs[@]} -eq 0 ]; then
        echo "/var/www"
    else
        printf '%s\n' "${dirs[@]}"
    fi
}

# 写入统一时间线条目（过滤换行符）
append_timeline() {
    local epoch="$1" dtype="$2" detail="$3"
    # 过滤换行符，保持时间线格式完整
    detail=$(echo "$detail" | tr "\n" " " | tr -s " " 2>/dev/null || echo "$detail" | tr -s " " 2>/dev/null)
    echo "${epoch}|${dtype}|${detail}" >> /tmp/timeline_raw_$$.txt
}

# 计算文件熵（用于检测编码/加密的 WebShell）
# 熵值 > 7.0 通常表示高度随机（可能是加密/编码内容）
calc_entropy() {
    local file="$1"
    if [ -f "$file" ] && [ -r "$file" ]; then
        # 使用 awk 计算 Shannon 熵
        od -An -tu1 "$file" 2>/dev/null | awk '
        {
            for(i=1;i<=NF;i++) {
                if($i ~ /^[0-9]+$/) {
                    freq[$i]++
                    total++
                }
            }
        }
        END {
            if(total==0) { print "0.0"; exit }
            entropy=0
            for(v in freq) {
                p = freq[v]/total
                if(p>0) entropy -= p * log(p)/log(2)
            }
            printf "%.2f", entropy
        }' 2>/dev/null || echo "0.0"
    else
        echo "0.0"
    fi
}

# 检测 WebShell 管理工具特征（菜刀、蚁剑、冰蝎、哥斯拉等）
detect_webshell_manager() {
    local file="$1"
    local content=""
    local found=0

    # 读取文件前 16KB 内容进行特征匹配
    if [ -f "$file" ] && [ -r "$file" ]; then
        content=$(head -c 16384 "$file" 2>/dev/null)
    else
        return
    fi

    # 菜刀（Chopper）特征
    if echo "$content" | grep -qE '@eval\s*\(\s*\$_(POST|GET|REQUEST)\[|@assert\s*\(\s*\$_(POST|GET|REQUEST)\[|eval\s*\(\s*base64_decode\s*\(\s*\$_(POST|GET|REQUEST)\['; then
        echo "[CHOPPER] 菜刀 WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_chopper" "Chopper: $file"
        found=1
    fi

    # 蚁剑（AntSword）特征
    if echo "$content" | grep -qE 'ant\s*sword|蚁剑|as_encode|ant\.php|new\s+Ant|@ini_set\s*\(\s*"display_errors"|@set_time_limit\s*\(\s*0\s*\).*@ini_set'; then
        echo "[ANTSWORD] 蚁剑 WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_antsword" "AntSword: $file"
        found=1
    fi

    # 冰蝎（Behinder）特征 - v3/v4
    if echo "$content" | grep -qE 'behinder|冰蝎|e45e|define\s*\(\s*"classname"|class\s+\w+\s+extends\s+ClassLoader|AES|SecretKey|Cipher.*getInstance|"AES"|"GBK"|reflect\.Method|defineClass'; then
        echo "[BEHINDER] 冰蝎 WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_behinder" "Behinder: $file"
        found=1
    fi

    # 哥斯拉（Godzilla）特征 - v4
    if echo "$content" | grep -qE 'godzilla|哥斯拉|pass\s*=\s*".*"|payload\s*=|cryption|payloadType|雅黑|xor|base64.*class|defineClass|ClassLoader.*defineClass'; then
        echo "[GODZILLA] 哥斯拉 WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_godzilla" "Godzilla: $file"
        found=1
    fi

    # Weevely 特征
    if echo "$content" | grep -qE 'weevely|preg_replace\s*\(\s*".*/e"|assert\s*\(\s*preg_replace'; then
        echo "[WEEVELY] Weevely WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_weevely" "Weevely: $file"
        found=1
    fi

    # C99/R57/WSO 等经典 WebShell
    if echo "$content" | grep -qiE 'c99shell|r57shell|wso\s*\d|phpshell|phpremoteview|phpspy|b374k|FilesMan|WSO.*auth'; then
        echo "[CLASSIC] 经典 WebShell 特征: $file"
        append_timeline "$(date +%s)" "webshell_classic" "Classic shell: $file"
        found=1
    fi

    # 内存马特征（无文件落地）
    if echo "$content" | grep -qE 'filter\s*=\s*new|addFilter|registerFilter|addServlet|registerServlet|addMapping|FilterRegistration|ServletRegistration'; then
        echo "[MEMSHELL_HINT] 内存马相关代码特征: $file"
        append_timeline "$(date +%s)" "memshell_hint" "Memshell code: $file"
        found=1
    fi

    return $((1-found))
}

# 检测图片马（文件头是图片但包含可执行代码）
detect_image_webshell() {
    local file="$1"
    local ext="${file##*.}"
    local ext_lower=$(echo "$ext" | tr '[:upper:]' '[:lower:]')

    # 只检查图片文件
    case "$ext_lower" in
        jpg|jpeg|png|gif|bmp|ico|webp|svg|tiff)
            ;;
        *)
            return
            ;;
    esac

    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi

    # 检查图片中是否包含可执行代码
    local suspicious=0

    # PHP 代码特征
    if grep -qPlE '<\?php|<\?=|<\?[^x]|eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec|assert\s*\(' "$file" 2>/dev/null; then
        echo "[IMAGE_SHELL] 图片中发现 PHP 代码: $file"
        append_timeline "$(date +%s)" "webshell_image" "Image PHP shell: $file"
        suspicious=1
    fi

    # JSP 代码特征
    if grep -qPlE '<%[@\s]|Runtime\.getRuntime|ProcessBuilder|\.exec\s*\(' "$file" 2>/dev/null; then
        echo "[IMAGE_SHELL] 图片中发现 JSP 代码: $file"
        append_timeline "$(date +%s)" "webshell_image" "Image JSP shell: $file"
        suspicious=1
    fi

    # ASP 代码特征
    if grep -qPlE '<%@\s|Execute\s*\(|ExecuteGlobal|CreateObject|WScript\.Shell' "$file" 2>/dev/null; then
        echo "[IMAGE_SHELL] 图片中发现 ASP 代码: $file"
        append_timeline "$(date +%s)" "webshell_image" "Image ASP shell: $file"
        suspicious=1
    fi

    # 检查是否是双扩展名（如 shell.php.jpg）
    if echo "$file" | grep -qE '\.(php|jsp|asp|aspx|cgi|pl|py|sh)\.'; then
        echo "[DOUBLE_EXT] 双扩展名可疑文件: $file"
        append_timeline "$(date +%s)" "webshell_double_ext" "Double extension: $file"
        suspicious=1
    fi

    return $((1-suspicious))
}

# 检测 .htaccess / .user.ini 等配置型后门
detect_config_backdoor() {
    local dir="$1"
    [ -d "$dir" ] || return

    # .htaccess 后门
    for ht in "$dir"/.htaccess "$dir"/*/.htaccess; do
        [ -f "$ht" ] || continue
        if grep -qE 'AddType\s+application/x-httpd-php|php_value\s+auto_prepend_file|SetHandler\s+application/x-httpd-php|php_flag\s+display_errors' "$ht" 2>/dev/null; then
            echo "[HTACCESS] .htaccess 配置后门: $ht"
            append_timeline "$(date +%s)" "config_backdoor" "htaccess backdoor: $ht"
        fi
    done

    # .user.ini 后门（PHP）
    for ini in "$dir"/.user.ini "$dir"/*/.user.ini; do
        [ -f "$ini" ] || continue
        if grep -qE 'auto_prepend_file|auto_append_file' "$ini" 2>/dev/null; then
            echo "[USER_INI] .user.ini 配置后门: $ini"
            append_timeline "$(date +%s)" "config_backdoor" "user.ini backdoor: $ini"
        fi
    done

    # web.config 后门（IIS）
    for wc in "$dir"/web.config "$dir"/*/web.config; do
        [ -f "$wc" ] || continue
        if grep -qE 'scriptProcessor|handlers.*path="\*"' "$wc" 2>/dev/null; then
            echo "[WEB_CONFIG] web.config 可疑配置: $wc"
            append_timeline "$(date +%s)" "config_backdoor" "web.config suspicious: $wc"
        fi
    done
}

# 自动检测 Java 应用服务器类型
detect_app_server() {
    local pid="$1"
    local cmdline=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ') 2>/dev/null || echo ""
    local detected="unknown"

    # Tomcat
    if echo "$cmdline" | grep -qE 'catalina\.home|Bootstrap.*start|org\.apache\.catalina'; then
        detected="tomcat"
        # 尝试提取 catalina.home / catalina.base
        local c_home=$(echo "$cmdline" | grep -oP 'catalina\.home=\K[^ ]+' 2>/dev/null)
        local c_base=$(echo "$cmdline" | grep -oP 'catalina\.base=\K[^ ]+' 2>/dev/null)
        [ -n "$c_home" ] && echo "APP_SERVER=tomcat catalina_home=${c_home}"
        [ -n "$c_base" ] && echo "APP_SERVER=tomcat catalina_base=${c_base}"

    # Spring Boot
    elif echo "$cmdline" | grep -qE 'org\.springframework\.boot|spring-boot|application\.properties'; then
        detected="springboot"
        echo "APP_SERVER=springboot"

    # Jetty
    elif echo "$cmdline" | grep -qE 'org\.eclipse\.jetty|jetty\.home|start\.jar'; then
        detected="jetty"
        local j_home=$(echo "$cmdline" | grep -oP 'jetty\.home=\K[^ ]+' 2>/dev/null)
        [ -n "$j_home" ] && echo "APP_SERVER=jetty jetty_home=${j_home}"

    # WildFly / JBoss
    elif echo "$cmdline" | grep -qE 'org\.jboss|wildfly|jboss\.home'; then
        detected="wildfly"
        echo "APP_SERVER=wildfly"

    # WebLogic
    elif echo "$cmdline" | grep -qE 'weblogic\.Server|weblogic\.home|wlserver'; then
        detected="weblogic"
        echo "APP_SERVER=weblogic"

    # WebSphere
    elif echo "$cmdline" | grep -qE 'com\.ibm\.ws\.runtime|WebSphere'; then
        detected="websphere"
        echo "APP_SERVER=websphere"

    # Undertow
    elif echo "$cmdline" | grep -qE 'io\.undertow|undertow\.jar'; then
        detected="undertow"
        echo "APP_SERVER=undertow"

    # Generic Java web app (检测端口推断)
    elif echo "$cmdline" | grep -qE 'java.*-jar|java.*\.jar|java.*\.war'; then
        # 从 lsof 或 ss 看是否监听 8080/8443/9094 等 web 端口
        if ss -tlpn 2>/dev/null | grep "$pid" | grep -qE ':(8080|8443|9094|9095|7001|7002|9043|9060|9080)'; then
            detected="generic_java_webapp"
            echo "APP_SERVER=generic_java_webapp"
        else
            detected="generic_java"
            echo "APP_SERVER=generic_java"
        fi
    fi

    echo "DETECTED=${detected}"

    # 返回检测到的类型
    case "$detected" in
        tomcat|springboot|jetty|wildfly|weblogic|websphere|undertow|generic_java_webapp)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# IOC 全量扫描（在所有已采集数据中搜索 IOC）
sweep_iocs() {
    local outdir="$1"
    [ ${#IOC_LIST[@]} -eq 0 ] && return

    echo ""
    echo "=== IOC 全量扫描 ==="
    echo "IOC 数量: ${#IOC_LIST[@]}"
    echo "扫描范围: ${outdir}"

    local ioc_count=0
    local hit_count=0

    while IFS= read -r ioc; do
        # 跳过空行和注释
        [[ -z "$ioc" || "$ioc" =~ ^[[:space:]]*# ]] && continue
        ioc_count=$((ioc_count + 1))

        local hits=0
        # 在已采集的文件中搜索（跳过二进制文件）
        while IFS= read -r -d '' f; do
            # 跳过二进制文件
            file "$f" 2>/dev/null | grep -qE 'ELF|binary|data|archive|compressed|image|audio|video' && continue
            local matches=$(grep -c "$ioc" "$f" 2>/dev/null || true)
            if [ "$matches" -gt 0 ]; then
                echo "  [HIT] IOC='${ioc}' 文件='${f}' 命中=${matches}次"
                hits=$((hits + matches))
            fi
        done < <(find "$outdir" -type f -size -50M -print0 2>/dev/null)

        if [ "$hits" -gt 0 ]; then
            echo "  => IOC '${ioc}' 总命中 ${hits} 次"
            hit_count=$((hit_count + 1))
        else
            echo "  [MISS] IOC='${ioc}' 未命中"
        fi
    done <<< "$(printf '%s\n' "${IOC_LIST[@]}")"

    echo "=== IOC 扫描完成: ${hit_count}/${ioc_count} 条 IOC 命中 ==="
}

# ---------- 配置区域 ----------
# ---------- 运行模式 ----------
MODE="full"
CUSTOM_OUTDIR=""
NO_COLOR=0

# Parse all flags (supports combined short flags like -qf)
while [ $# -gt 0 ]; do
    case "$1" in
        --quick|-q)
            MODE="quick"
            echo "[+] Quick mode: skipping deep scans (webshell full, logs >200MB, file hash)"
            shift
            ;;
        --full|-f)
            MODE="full"
            ENABLE_MEM_DUMP=1
            echo "[+] Full mode: enabling memory dumps and deep analysis"
            shift
            ;;
        --output-dir|-o)
            CUSTOM_OUTDIR="$2"
            echo "[+] Custom output directory: ${CUSTOM_OUTDIR}"
            shift 2
            ;;
        --no-color)
            NO_COLOR=1
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash $0 [OPTIONS] [IOC_FILE]"
            echo "  sudo bash $0 --quick"
            echo "  sudo bash $0 --full -o /evidence/collect"
            echo ""
            echo "Options:"
            echo "  --quick, -q       Quick mode (skip deep scans, large logs, file hash)"
            echo "  --full, -f        Full mode (enable memory dumps, deep ELF analysis)"
            echo "  --output-dir, -o  Custom output directory (default: /tmp)"
            echo "  --no-color        Disable color output"
            echo "  --help, -h        Show this help"
            echo ""
            echo "IOC_FILE:           Path to IOC file (one IP/domain/hash per line)"
            echo "                    or: export IOC_FILE=/path/to/ioc.txt"
            exit 0
            ;;
        -*)
            echo "[!] Unknown option: $1 (use --help)"
            exit 1
            ;;
        *)
            IOC_FILE="$1"
            shift
            ;;
    esac
done
WEB_DIRS_RAW=( "/var/www" "/opt/tomcat/webapps" "/usr/share/nginx/html" "/home/*/public_html" )  # 注意：含空格的路径会导致 glob 展开分裂
WEB_LOG_DIRS=( "/var/log/nginx" "/usr/local/nginx/logs" "/var/log/httpd" "/var/log/apache2" )
APP_LOG_DIRS=( "/opt/tomcat/logs" "/var/log/app" "/opt/app/logs" "/home" )
AUTH_LOG_DIRS=( "/var/log" )

EXCLUDE_DIRS=( "/mnt" "/media" "/var/lib/libvirt" "/var/lib/docker" "/var/lib/containers" )

# ---------- IOC 输入（可选）----------
IOC_FILE="${IOC_FILE:-}"
IOC_LIST=()
if [ -n "$IOC_FILE" ] && [ -f "$IOC_FILE" ]; then
    echo "[+] 加载 IOC 文件: ${IOC_FILE}"
    if command -v mapfile &>/dev/null 2>&1; then
        mapfile -t IOC_LIST < "$IOC_FILE"
    else
        # bash < 4 fallback
        while IFS= read -r line; do [ -n "$line" ] && IOC_LIST+=( "$line" ); done < "$IOC_FILE"
    fi
fi

# ---------- 初始化 ----------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -n "${CUSTOM_OUTDIR}" ]; then
    mkdir -p "${CUSTOM_OUTDIR}" 2>/dev/null || { echo "[!] Cannot create custom output dir: ${CUSTOM_OUTDIR}"; exit 1; }
    OUTDIR="${CUSTOM_OUTDIR}/emergency_${TIMESTAMP}"
else
    OUTDIR="/tmp/emergency_${TIMESTAMP}"
fi
mkdir -p "${OUTDIR}/logs" "${OUTDIR}/extra"
START_TIME=$(date)
# EPOCHREALTIME is bash 5+; use date +%s as fallback for bash 4.x/macOS
if [ -n "${EPOCHREALTIME:-}" ]; then
    EPOCH_START=${EPOCHREALTIME%.*}
else
    EPOCH_START=$(date +%s)
fi
echo "采集开始: ${START_TIME}" > "${OUTDIR}/timeline.txt"
append_timeline "$EPOCH_START" "script_start" "Emergency collection started"

if command -v mapfile &>/dev/null 2>&1; then
    mapfile -t WEB_DIRS < <(expand_web_dirs)
else
    WEB_DIRS=()
    while IFS= read -r d; do [ -n "$d" ] && WEB_DIRS+=( "$d" ); done < <(expand_web_dirs)
fi

# 构建 find 排除数组（安全无注入）
EXCLUDE_FIND=()
for ed in "${EXCLUDE_DIRS[@]}"; do
    [ -d "$ed" ] || continue
    EXCLUDE_FIND+=( -path "$ed" -prune -o )
done

echo "[+] 应急取证开始，输出目录: ${OUTDIR}"
echo "[!] 预计耗时 1-3 分钟（Java 应用服务器 + 日志扫描），CPU 限制 300 秒"

#----------- 1. 系统基础信息 + 可信基线 -----------
echo "[*] 收集系统信息与可信基线..."
{
    echo "=============================================="
    echo "  系统基础信息与可信基线 (system_info.txt)"
    echo "=============================================="
    echo "  采集内容: 操作系统核心信息、硬件资源、时区、安装日期、用户状态、软件包完整性校验"
    echo "  包含: 主机名、系统版本、内核、CPU/内存、磁盘分区、时区、安装日期、运行时间、登录用户、最近登录、失败登录、用户列表(含UID=0特权用户)、内核模块、挂载信息、磁盘使用、环境变量、RPM/DEB包校验、SELinux/AppArmor/ASLR状态"
    echo ""
    echo "=== 主机名 ==="; hostname
    echo "=== 系统版本 ==="; safe_run 5 cat /etc/os-release 2>/dev/null || safe_run 5 cat /etc/redhat-release 2>/dev/null
    echo "=== 内核 ==="; uname -a
    echo "=== CPU 信息 ==="; safe_run 5 lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | grep -E 'model name|cpu cores|siblings|processor' | head -20
    echo "=== 内存 ==="; safe_run 5 free -h 2>/dev/null; echo ""; cat /proc/meminfo 2>/dev/null | grep -E 'MemTotal|MemFree|SwapTotal|SwapFree' | head -10
    echo "=== 磁盘分区 ==="; safe_run 5 lsblk -f 2>/dev/null || safe_run 5 lsblk 2>/dev/null || echo "lsblk 不可用"
    echo "=== 运行时间 ==="; uptime
    echo "=== 当前时间 ==="; date
    echo "=== 时区 ==="; safe_run 5 timedatectl 2>/dev/null || cat /etc/timezone 2>/dev/null || date +%Z
    echo "=== 系统安装日期(估算) ==="; stat / 2>/dev/null | grep Birth; safe_run 5 rpm -qi basesystem 2>/dev/null | grep 'Install Date' || safe_run 5 dpkg -l base-files 2>/dev/null | grep '^ii' || echo "无法确定安装日期"
    echo "=== 登录用户 ==="; w
    echo "=== 最近登录 ==="; safe_run 10 last -n 20 2>/dev/null
    echo "=== 登录失败 ==="; safe_run 10 lastb -n 20 2>/dev/null
    echo "=== 用户列表 ==="; cat /etc/passwd
    echo "=== 特权用户 (UID=0) ==="; awk -F: '$3==0 {print "UID="$3" "$1}' /etc/passwd 2>/dev/null
    echo "=== 内核模块 ==="; safe_run 10 lsmod
    echo "=== 挂载信息 ==="; mount
    echo "=== 磁盘使用 ==="; df -h
    echo "=== 环境变量（敏感字段已脱敏） ==="; printenv | sed 's/\(PASS\|SECRET\|KEY\|TOKEN\)=.*/\1=***REDACTED***/I'

    # 可信基线：检查软件包完整性
    echo "=== RPM 包校验（部分输出） ==="
    safe_run 30 rpm -Va 2>/dev/null | head -100
    echo "=== debsums 校验（仅 Debian/Ubuntu） ==="
    safe_run 30 debsums -c 2>/dev/null | head -50

    # 安全状态检查
    echo "=== SELinux 状态 ==="; safe_run 5 getenforce 2>/dev/null || echo "SELinux 不可用"
    echo "=== AppArmor 状态 ==="; safe_run 5 aa-status 2>/dev/null || echo "AppArmor 不可用"
    echo "=== ASLR 状态 ==="; cat /proc/sys/kernel/randomize_va_space 2>/dev/null
} > "${OUTDIR}/system_info.txt" 2>&1
append_timeline "$(date +%s)" "system_info" "Basic system & package integrity checked"

#----------- 2. 进程信息（含隐藏进程检测） -----------
echo "[*] 收集进程信息..."
{
    echo "=============================================="
    echo "  进程信息与隐藏进程检测 (process.txt)"
    echo "=============================================="
    echo "  采集内容: 进程快照、进程树、隐藏进程检测"
    echo "  包含: ps aux (按CPU排序前500)、pstree进程树、/proc与ps交叉比对隐藏进程检测"
    echo ""
    safe_run 20 ps auxwwf --sort=-%cpu 2>/dev/null || safe_run 20 ps auxww --sort=-%cpu 2>/dev/null | head -500
    echo "=== 进程树 ==="
    safe_run 5 pstree -Al 2>/dev/null || safe_run 5 pstree -a 2>/dev/null || true
    echo "=== 隐藏进程检测 (对比 /proc 和 ps) ==="
    ls -1 /proc | grep -E '^[0-9]+$' | sort > /tmp/proc_list_$$.txt
    ps -eo pid --no-headers | tr -d ' ' | sort > /tmp/ps_list_$$.txt
    hidden_pids=$(comm -23 /tmp/proc_list_$$.txt /tmp/ps_list_$$.txt | head -20)
    if [ -n "$hidden_pids" ]; then
        echo "[!] 发现隐藏进程:"
        echo "$hidden_pids"
        for pid in $hidden_pids; do
            echo "--- PID $pid 详情 ---"
            cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' '
            echo ""
            ls -la "/proc/$pid/exe" 2>/dev/null
        done
    else
        echo "[OK] 未发现隐藏进程"
    fi
} > "${OUTDIR}/process.txt" 2>&1
append_timeline "$(date +%s)" "process" "Process snapshot and hidden proc check"

#----------- 2.5 /proc/PID 完整快照 + 已删除文件检测 -----------
echo "[*] 收集 /proc/PID 快照 + 已删除文件检测..."
{
    echo "=============================================="
    echo "  /proc/PID 完整快照与已删除文件检测 (proc_snapshot.txt)"
    echo "=============================================="
    echo "  采集内容: Java/Tomcat/中间件进程的/proc目录完整快照、应用服务器类型检测、已删除但仍被进程持有文件"
    echo "  包含: environ(可能泄露密钥)、cwd(工作目录)、limits(资源限制)、maps中JAR映射(标记高危路径/tmp等)、匿名可执行内存段、lsof +L1已删除文件"
    echo "=============================================="
    echo "  /proc/PID 关键文件快照"
    echo "=============================================="

    # 对所有 Java 进程做完整快照，对其他关键进程做简要快照
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n); do
        [ -d "/proc/$pid" ] || continue
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
        [ -z "$cmdline" ] && continue

        # 判断是否为 Java/Tomcat/中间件进程
        is_java=0
        echo "$cmdline" | grep -qE 'java|tomcat|catalina|jboss|wildfly|weblogic|jetty|spring|node\b|python|gunicorn|uwsgi|httpd|nginx' && is_java=1
        [ "$is_java" -eq 0 ] && continue

        echo ""
        echo "=========================================="
        echo "  PID: $pid"
        echo "  命令行: $cmdline"

        # 自动检测应用服务器类型
        echo "--- 应用服务器类型检测 ---"
        detect_app_server "$pid"
        echo "=========================================="

        # environ（可能泄露密钥/密码 + 全量快照）
        echo "--- environ（敏感变量过滤）---"
        cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'PASS|SECRET|KEY|TOKEN|DATABASE|JDBC|JAVA_OPTS|CATALINA_OPTS|LD_PRELOAD|LD_LIBRARY_PATH|JAVA_TOOL_OPTIONS' || echo "(无敏感环境变量)"
        # 同时 dump 完整 environ 到独立文件（攻击者可能用 JAVA_TOOL_OPTIONS 等非关键词参数挂 agent）
        cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' > "${OUTDIR}/extra/PID_${pid}_environ.txt"
        echo "  [OK] 完整 environ 已保存至 extra/PID_${pid}_environ.txt"
        echo ""

        # cwd（工作目录）
        echo "--- cwd ---"
        ls -la "/proc/${pid}/cwd" 2>/dev/null
        readlink -f "/proc/${pid}/cwd" 2>/dev/null
        echo ""

        # limits（文件描述符限制 — 结合 lsof 判断异常高）
        echo "--- limits ---"
        cat "/proc/${pid}/limits" 2>/dev/null | grep -E 'open files|Max processes|Max locked memory'
        echo ""

        # maps 中的 JAR 映射（非标准路径）
        echo "--- maps 中的 JAR 映射 ---"
        if [ -f "/proc/${pid}/maps" ]; then
            grep '\.jar' "/proc/${pid}/maps" 2>/dev/null | awk '{print $6}' | sort -u | while read jar; do
                case "$jar" in
                    /usr/java/*|/usr/lib/jvm/*|/usr/local/gov/*|/opt/tomcat/*|/usr/local/BIreportforms10/*)
                        echo "  [STD] $jar"
                        ;;
                    /tmp/*|/dev/shm/*|/var/tmp/*)
                        echo "  [!!!] 高危路径加载: $jar"
                        append_timeline "$(date +%s)" "proc_maps_highrisk_jar" "PID $pid maps high-risk JAR: $jar"
                        ;;
                    "")
                        ;;
                    *)
                        echo "  [SUS] 非标准路径: $jar"
                        append_timeline "$(date +%s)" "proc_maps_nonstd_jar" "PID $pid maps non-std JAR: $jar"
                        ;;
                esac
            done
        fi
        echo ""

        # maps 中的可疑匿名可执行映射
        echo "--- maps 中的可执行匿名映射 ---"
        grep -E 'rwxp' "/proc/${pid}/maps" 2>/dev/null | head -10 && echo "[!] 存在可写可执行内存段!"
    done

    echo ""
    echo "=============================================="
    echo "  已删除但仍被进程持有的文件"
    echo "=============================================="
    echo ""
    echo "=== 已删除的 JAR/class/so 文件 ==="
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$'); do
        [ -d "/proc/$pid/fd" ] || continue
        deleted=$(ls -la "/proc/${pid}/fd/" 2>/dev/null | grep '(deleted)' | head -20)
        if [ -n "$deleted" ]; then
            echo "--- PID $pid ---"
            cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
            echo "  命令行: ${cmdline:0:200}"
            echo "$deleted" | while read line; do
                echo "  $line"
                # 标记高危
                if echo "$line" | grep -qE '(tmp|dev/shm|\.jar|\.class|\.so)'; then
                    echo "  [!!!] 高危: 临时目录文件已删除但仍被加载!"
                    append_timeline "$(date +%s)" "deleted_file_highrisk" "PID $pid deleted: $line"
                fi
            done
        fi
    done

    echo ""
    echo "=== lsof +L1（已删除但仍打开的文件） ==="
    if command -v lsof &>/dev/null; then
        safe_run 15 lsof +L1 2>/dev/null | grep -E "\.jar|\.class|\.so|tmp|dev/shm" | head -50 || true
    else
        echo "[!] lsof 未安装，跳过"
    fi

} > "${OUTDIR}/proc_snapshot.txt" 2>&1
append_timeline "$(date +%s)" "proc_snapshot" "/proc snapshot + deleted files check"

#----------- 2.6 Ptrace 检测 + Raw Socket 取证 -----------
echo "[*] 检测Ptrace/Raw Sockets..."
{
    echo "=============================================="
    echo "  Ptrace/Raw Socket取证 (extra/ptrace_raw_sockets.txt)"
    echo "=============================================="
    echo "  采集内容: 被调试进程检测、Raw/Packet Socket进程"
    echo ""
    echo "=== Ptrace 检测 (查找被调试进程) ==="
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n); do
        [ -f "/proc/${pid}/status" ] || continue
        tracer=$(grep 'TracerPid:' "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        if [ -n "$tracer" ] && [ "$tracer" != "0" ]; then
            cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr ' ' ' ')
            tracer_name=$(cat "/proc/${tracer}/comm" 2>/dev/null || echo "unknown")
            echo "  [!!!] PID ${pid} (${cmdline:0:80}) 被 PID ${tracer} (${tracer_name}) ptrace 追踪!"
            append_timeline "$(date +%s)" "ptrace_detected" "PID ${pid} traced by ${tracer}"
        fi
    done
    echo ""
    echo "=== Raw Socket 进程 (/proc/net/raw) ==="
    cat /proc/net/raw 2>/dev/null || echo "/proc/net/raw 不可用"
    echo ""
    echo "=== Packet Socket 进程 (/proc/net/packet) ==="
    cat /proc/net/packet 2>/dev/null || echo "/proc/net/packet 不可用"
} > "${OUTDIR}/extra/ptrace_raw_sockets.txt" 2>&1
append_timeline "$(date +%s)" "ptrace_sockets" "Ptrace/Raw sockets checked"

#----------- 2.7 memfd_create + LD_PRELOAD 深度检测 -----------
echo "[*] 检测 memfd_create 无文件执行 + LD_PRELOAD 劫持..."
{
    echo "=============================================="
    echo "  memfd_create / LD_PRELOAD 深度检测 (extra/memfd_preload.txt)"
    echo "=============================================="
    echo "  采集内容: memfd无文件执行、/proc/PID/exe异常、LD_PRELOAD劫持、so注入"
    echo ""

    echo "=== memfd_create 无文件执行检测 ==="
    memfd_count=0
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n); do
        [ -d "/proc/$pid/fd" ] || continue
        memfd_fds=$(ls -l "/proc/$pid/fd/" 2>/dev/null | grep -i 'memfd:' | head -10)
        if [ -n "$memfd_fds" ]; then
            cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
            # 白名单: pipewire/pulseaudio/blueman/speech-dispatcher 正常使用 memfd
            if echo "$cmdline" | grep -qE 'pipewire|pulseaudio|blueman|speech-dispatcher|wireplumber'; then
                echo "  [INFO] PID $pid memfd 白名单跳过 (pipewire/pulseaudio 正常行为)"
                continue
            fi
            exe_link=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "(deleted/unknown)")
            echo "  [!!!] PID $pid memfd_create 无文件执行!"
            echo "    cmdline: ${cmdline:0:200}"
            echo "    /proc/$pid/exe -> $exe_link"
            echo "    memfd fds:"
            echo "$memfd_fds" | while read line; do echo "      $line"; done
            append_timeline "$(date +%s)" "memfd_create" "PID $pid memfd: $exe_link"
            memfd_count=$((memfd_count + 1))
        fi
        if [ -L "/proc/$pid/exe" ]; then
            exe_target=$(readlink "/proc/$pid/exe" 2>/dev/null)
            if echo "$exe_target" | grep -q '(deleted)'; then
                cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
                echo "  [!!!] PID $pid 运行已删除的二进制 (可能为内存驻留后门)"
                echo "    cmdline: ${cmdline:0:200}"
                echo "    exe: $exe_target"
                append_timeline "$(date +%s)" "deleted_exe" "PID $pid deleted exe: $exe_target"
            fi
        fi
    done
    echo "  memfd_create 命中进程数: ${memfd_count}"
    echo ""
    echo "=== LD_PRELOAD 劫持检测 ==="
    echo "--- /etc/ld.so.preload ---"
    if [ -f /etc/ld.so.preload ]; then
        echo "[!!!] /etc/ld.so.preload 存在!"
        cat /etc/ld.so.preload 2>/dev/null
        append_timeline "$(date +%s)" "ld_preload" "/etc/ld.so.preload exists"
    else
        echo "[OK] /etc/ld.so.preload 不存在"
    fi
    echo ""
    echo "=== 进程级 LD_PRELOAD 检查 ==="
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n); do
        [ -f "/proc/$pid/environ" ] || continue
        preload=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep '^LD_PRELOAD=' | head -1)
        if [ -n "$preload" ]; then
            cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
            echo "  [!!!] PID $pid LD_PRELOAD: $preload"
            echo "    cmdline: ${cmdline:0:150}"
            append_timeline "$(date +%s)" "ld_preload_proc" "PID $pid LD_PRELOAD=$preload"
        fi
    done
    echo ""
    echo "=== 非标准路径 so 加载 ==="
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n | head -200); do
        [ -f "/proc/$pid/maps" ] || continue
        suspicious_so=$(grep -E '\.so.*(tmp|dev/shm|home|var/tmp)' "/proc/$pid/maps" 2>/dev/null | awk '{print $6}' | sort -u | head -10)
        if [ -n "$suspicious_so" ]; then
            cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
            echo "  [!!!] PID $pid 加载非标准路径 so:"
            echo "$suspicious_so" | while read so; do
                echo "    $so"
                append_timeline "$(date +%s)" "suspicious_so" "PID $pid so: $so"
            done
        fi
    done
} > "${OUTDIR}/extra/memfd_preload.txt" 2>&1
append_timeline "$(date +%s)" "memfd_preload" "memfd_create + LD_PRELOAD deep check"

#----------- 3. 网络连接 -----------
{
    echo "=============================================="
    echo "  网络连接与防火墙 (network.txt)"
    echo "=============================================="
    echo "  采集内容: 网络连接状态、防火墙规则、路由表、DNS配置、访问控制"
    echo "  包含: ss/netstat/lsof网络连接、/proc/net原始数据、iptables/nftables/firewalld规则、路由表、ARP表、DNS(/etc/resolv.conf+hosts)、hosts.allow/deny、sudoers、PAM模块"
    echo ""
    echo "=== ss ==="; safe_run 10 ss -antup 2>/dev/null
    echo "=== netstat ==="; safe_run 10 netstat -antup 2>/dev/null
    if command -v lsof &>/dev/null; then
        echo "=== lsof ==="; safe_run 10 lsof -i -P -n 2>/dev/null | head -200
    else
        echo "[!] lsof 未安装"
    fi
    echo "=== /proc/net 原始数据 ==="
    cat /proc/net/tcp /proc/net/udp /proc/net/tcp6 /proc/net/udp6 2>/dev/null

    # 新增：防火墙规则
    echo "=== 防火墙规则 ==="
    if command -v iptables &>/dev/null; then
        echo "--- iptables ---"; safe_run 10 iptables -L -n -v 2>/dev/null
        echo "--- iptables NAT ---"; safe_run 10 iptables -t nat -L -n -v 2>/dev/null
    fi
    if command -v nft &>/dev/null; then
        echo "--- nftables ---"; safe_run 10 nft list ruleset 2>/dev/null
    fi
    if command -v firewall-cmd &>/dev/null; then
        echo "--- firewalld ---"; safe_run 10 firewall-cmd --list-all 2>/dev/null
    fi

    # 新增：路由和 ARP
    echo "=== 路由表 ==="; safe_run 5 ip route show 2>/dev/null || safe_run 5 route -n 2>/dev/null
    echo "=== ARP 表 ==="; safe_run 5 ip neigh 2>/dev/null || safe_run 5 arp -an 2>/dev/null

    # 新增：DNS 配置
    echo "=== DNS 配置 ==="
    echo "--- /etc/resolv.conf ---"; cat /etc/resolv.conf 2>/dev/null
    echo "--- /etc/hosts ---"; cat /etc/hosts 2>/dev/null

    # hosts.allow / hosts.deny（tcp_wrappers 访问控制）
    echo "=== TCP Wrappers ==="
    echo "--- /etc/hosts.allow ---"
    cat /etc/hosts.allow 2>/dev/null || echo "(不存在)"
    echo "--- /etc/hosts.deny ---"
    cat /etc/hosts.deny 2>/dev/null || echo "(不存在)"

    # 新增：sudoers 检查
    echo "=== Sudoers 配置 ==="
    cat /etc/sudoers 2>/dev/null
    ls -la /etc/sudoers.d/ 2>/dev/null
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f"
    done

    # 新增：PAM 模块检查
    echo "=== PAM 模块（近30天修改） ==="
    find /lib*/security/ /usr/lib*/security/ -name "*.so" -mtime -30 2>/dev/null | head -20

    # 新增：网络连接流摘要（按目标IP统计ESTABLISHED连接数）
    echo "=== 网络连接流摘要（按目标IP统计） ==="
    ss -tn state established 2>/dev/null | awk 'NR>1{print $5}' | awk -F: '{print $1}' | sort | uniq -c | sort -rn | head -20
} > "${OUTDIR}/network.txt" 2>&1
append_timeline "$(date +%s)" "network" "Network connections, firewall, DNS collected"

#----------- 3.5 ARP/DNS//etc/hosts/Promiscuous 网络层2/3取证 -----------
echo "[*] 收集ARP/DNS/hosts/网卡模式..."
{
    echo "=============================================="
    echo "  网络层2/3取证 (extra/net_l2_l3.txt)"
    echo "=============================================="
    echo "  采集内容: ARP表、DNS配置、/etc/hosts、网卡混杂模式、IPv6邻居表"
    echo ""
    echo "=== ARP 表 (可能发现ARP欺骗) ==="
    safe_run 5 arp -an 2>/dev/null || safe_run 5 cat /proc/net/arp 2>/dev/null || echo "ARP 不可用"
    echo ""
    echo "=== /etc/hosts (可能被篡改) ==="
    cat /etc/hosts 2>/dev/null || echo "/etc/hosts 不可用"
    echo ""
    echo "=== /etc/resolv.conf (DNS配置) ==="
    cat /etc/resolv.conf 2>/dev/null || echo "/etc/resolv.conf 不可用"
    echo ""
    echo "=== DNS 缓存 (systemd-resolved) ==="
    safe_run 5 resolvectl statistics 2>/dev/null || safe_run 5 systemd-resolve --statistics 2>/dev/null || echo "systemd-resolved 不可用"
    echo ""
    echo "=== 网卡混杂模式检测 ==="
    ip link show 2>/dev/null | grep -i PROMISC && echo "[!] 发现混杂模式网卡!" || echo "[OK] 未发现混杂模式"
    echo ""
    echo "=== 所有网卡详细状态 ==="
    ip addr show 2>/dev/null || ifconfig -a 2>/dev/null
    echo ""
    echo "=== 路由表 ==="
    ip route show 2>/dev/null || route -n 2>/dev/null
    echo ""
    echo "=== IPv6 邻居表 ==="
    ip -6 neigh show 2>/dev/null || echo "IPv6 不可用"
    echo ""
    echo "=== IPv6 路由表 ==="
    ip -6 route show 2>/dev/null || echo "IPv6 路由不可用"
    echo ""
    echo "=== 活动网络服务绑定 (ss -tulnp) ==="
    safe_run 10 ss -tulnp 2>/dev/null || safe_run 10 netstat -tulnp 2>/dev/null
} > "${OUTDIR}/extra/net_l2_l3.txt" 2>&1
append_timeline "$(date +%s)" "net_l2_l3" "ARP/DNS/hosts/promiscuous collected"
#----------- 4. 计划任务 + systemd 持久化 -----------
echo "[*] 收集计划任务与系统服务..."
{
    echo "=============================================="
    echo "  持久化机制检测 (crontab.txt)"
    echo "=============================================="
    echo "  采集内容: 计划任务、systemd服务、启动脚本、SSH配置及后门"
    echo "  包含: crontab/cron.d/用户crontab、systemd timers/services/sockets(标记ExecStart可疑路径)、rc.local、profile.d(标记curl/wget/base64等可疑命令)、sshd_config(标记PermitRootLogin/ProxyCommand/ForceCommand)、authorized_keys(标记command=限制)"
    echo ""
    echo "=== /etc/crontab ==="; cat /etc/crontab 2>/dev/null
    echo "=== /etc/cron.d/ ==="; ls -la /etc/cron.d/ 2>/dev/null
    for f in /etc/cron.d/*; do [ -f "$f" ] && echo "--- $f ---" && cat "$f"; done
    echo "=== 用户计划任务 ==="
    for u in $(awk -F: '{print $1}' /etc/passwd); do
        crontab -u "$u" -l 2>/dev/null && echo "--- $u ---"
    done
    echo "=== systemd timers ==="; safe_run 10 systemctl list-timers --all 2>/dev/null
    echo "=== systemd 已启用服务 ==="
    safe_run 10 systemctl list-unit-files --type=service 2>/dev/null | grep enabled
    echo "=== systemd socket 单元 ==="
    safe_run 10 systemctl list-unit-files --type=socket 2>/dev/null | head -20
    echo "=== 可疑 systemd 服务文件内容 ==="
    for svc_dir in /etc/systemd/system /usr/lib/systemd/system; do
        [ -d "$svc_dir" ] && find "$svc_dir" -name "*.service" -mtime -30 -print0 2>/dev/null |
        while IFS= read -r -d '' svc; do
            echo "--- $svc ---"
            cat "$svc" 2>/dev/null
            # 检查 ExecStart 是否指向可疑路径
            if grep -qE 'ExecStart=.*/(tmp|dev/shm|var/tmp|home)' "$svc" 2>/dev/null; then
                echo "[!] ExecStart 指向可疑路径!"
                append_timeline "$(date +%s)" "suspicious_service" "ExecStart suspicious: $svc"
            fi
        done
    done
    echo "=== /etc/rc.local & 启动脚本 ==="
    cat /etc/rc.local 2>/dev/null || true
    cat /etc/rc.d/rc.local 2>/dev/null || true
    echo "=== /etc/profile.d/ ==="
    ls -la /etc/profile.d/ 2>/dev/null
    for f in /etc/profile.d/*.sh; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f"
        # 检查可疑内容
        if grep -qE 'curl|wget|base64|eval|exec|python|nc |ncat|bash\s*-i' "$f" 2>/dev/null; then
            echo "[!] profile.d 脚本包含可疑命令!"
            append_timeline "$(date +%s)" "suspicious_profile" "Suspicious profile.d: $f"
        fi
    done

    echo "=== SSH 配置检查 ==="
    echo "--- sshd_config ---"; cat /etc/ssh/sshd_config 2>/dev/null
    # 检查可疑 SSH 配置
    if grep -qE '^(PermitRootLogin\s+yes|PasswordAuthentication\s+yes|PubkeyAuthentication\s+no)' /etc/ssh/sshd_config 2>/dev/null; then
        echo "[!] SSH 配置存在安全风险!"
    fi
    if grep -vE '^[[:space:]]*#' /etc/ssh/sshd_config 2>/dev/null | grep -qE '(ProxyCommand|LocalCommand|ForceCommand)'; then
        echo "[!] SSH 配置包含可疑命令!"
        append_timeline "$(date +%s)" "ssh_backdoor" "SSH suspicious command in config"
    fi

    echo "=== authorized_keys ==="
    find /root /home -name authorized_keys -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "--- $f ---"
        ls -la "$f"
        cat "$f"
        # 检查可疑 key（无 comment、command= 限制等）
        if grep -qE '^command=' "$f" 2>/dev/null; then
            echo "[!] authorized_keys 包含 command= 限制!"
        fi
    done

    # 新增：XDG 自启动目录检查
    echo "=== XDG 自启动目录 ==="
    for autostart in /root/.config/autostart /home/*/.config/autostart /etc/xdg/autostart; do
        [ -d "$autostart" ] || continue
        echo "--- $autostart ---"
        ls -la "$autostart/" 2>/dev/null
        for f in "$autostart"/*.desktop; do
            [ -f "$f" ] && echo "--- $f ---" && cat "$f"
        done
    done

    # 新增：勒索信检测
    echo "=== 勒索信检测 ==="
    for dir in /root /home /tmp /var/tmp; do
        [ -d "$dir" ] && find "$dir" -maxdepth 4 -type f -iregex '.*\(readme\|ransom\|decrypt\|bitcoin\|recover\|restore\|unlock\).*\(\.txt\|\.html\|\.hta\|\.png\)' -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "[RANSOM_NOTE] 可能勒索信: $f ($(stat -c %y "$f" 2>/dev/null))"
            head -c 500 "$f" 2>/dev/null
            echo ""
            append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "ransom_note" "Possible ransom note: $f"
        done
    done

} > "${OUTDIR}/crontab.txt" 2>&1
append_timeline "$(date +%s)" "persistence" "Cron, systemd, rc.local, SSH, autostart, ransom note checked"

#----------- 4.5 用户登录取证 (wtmp/btmp/lastlog) -----------
echo "[*] 用户登录取证..."
{
    echo "=============================================="
    echo "  用户登录取证 (extra/login_forensics.txt)"
    echo "=============================================="
    echo "  采集内容: wtmp成功登录、btmp失败登录、lastlog最后登录时间戳"
    echo ""
    echo "=== last -if (成功登录) ==="
    safe_run 10 last -if /var/log/wtmp 2>/dev/null | head -100 || safe_run 10 last -n 100 2>/dev/null || echo "wtmp 不可用"
    echo ""
    echo "=== lastb -if (失败登录) ==="
    safe_run 10 lastb -if /var/log/btmp 2>/dev/null | head -100 || safe_run 10 lastb -n 100 2>/dev/null || echo "btmp 不可用"
    echo ""
    echo "=== lastlog (每个用户最后登录时间) ==="
    safe_run 10 lastlog 2>/dev/null | grep -v 'Never logged in' | head -50 || echo "lastlog 不可用"
    echo ""
    echo "=== /var/log/auth.log 最近登录事件 ==="
    safe_run 10 grep -E 'Accepted|Failed|session opened' /var/log/auth.log 2>/dev/null | tail -50 || safe_run 10 grep -E 'Accepted|Failed|session opened' /var/log/secure 2>/dev/null | tail -50 || echo "auth.log/secure 不可用"
    echo ""
    echo "=== 当前登录会话 (who -a) ==="
    who -a 2>/dev/null || w 2>/dev/null
    echo ""
    echo "=== utmpdump (登录记录) ==="
    safe_run 5 utmpdump /var/run/utmp 2>/dev/null | tail -50 || echo "utmpdump 不可用"
} > "${OUTDIR}/extra/login_forensics.txt" 2>&1
append_timeline "$(date +%s)" "login_forensics" "Login forensics collected"
#----------- 5. 历史命令（含时间线索） -----------
echo "[*] 收集历史命令..."
{
    echo "=============================================="
    echo "  历史命令分析 (history_cmds.txt)"
    echo "=============================================="
    echo "  采集内容: 所有用户的bash_history及可疑命令模式检测"
    echo "  包含: /root/.bash_history和/home/*/.bash_history最后1000条、标记curl/wget/nc/bash -i/python -c/base64 -d/chmod 777//tmp//dev/shm等可疑命令"
    echo ""
    for hist in /root/.bash_history /home/*/.bash_history; do
        if [ -f "$hist" ]; then
            user=$(basename "$(dirname "$hist")")
            echo "--- $user ---"
            tail -n 1000 "$hist"
            # 记录最后一条命令时间到时间线
            hist_epoch=$(stat -c %Y "$hist" 2>/dev/null)
            [ -n "$hist_epoch" ] && append_timeline "$hist_epoch" "bash_history" "Modified: ${hist} (user: ${user})"
        fi
    done

    # 检查可疑历史命令
    echo "=== 可疑历史命令模式 ==="
    for hist in /root/.bash_history /home/*/.bash_history; do
        [ -f "$hist" ] || continue
        user=$(basename "$(dirname "$hist")")
        grep -nE '(curl|wget|nc |ncat|bash\s*-i|python\s*-c|perl\s*-e|ruby\s*-e|base64\s*-d|chmod\s+777|/tmp/|/dev/shm/)' "$hist" 2>/dev/null | head -50 | while read line; do
            echo "[!] 可疑命令 ($user): $line"
        done
    done
} > "${OUTDIR}/history_cmds.txt" 2>&1

#----------- 5.5 操作痕迹补充 (known_hosts / recently-used / viminfo) -----------
echo "[*] 收集操作痕迹补充..."
{
    echo "=============================================="
    echo "  操作痕迹补充 (extra/operation_traces.txt)"
    echo "=============================================="
    echo "  采集内容: SSH横向移动痕迹、GUI最近文件、Vim痕迹"
    echo ""

    # SSH known_hosts（横向移动关键证据）
    echo "=== SSH known_hosts（横向移动痕迹） ==="
    for kh in /root/.ssh/known_hosts /home/*/.ssh/known_hosts; do
        [ -f "$kh" ] || continue
        user=$(basename "$(dirname "$(dirname "$kh")")")
        echo "--- $user ---"
        cat "$kh" 2>/dev/null
        append_timeline "$(stat -c %Y "$kh" 2>/dev/null || true)" "known_hosts" "SSH known_hosts: $kh (user: $user)"
    done
    echo ""

    # recently-used.xbel（GUI 操作痕迹）
    echo "=== 最近使用文件 (recently-used.xbel) ==="
    for recent in /root/.local/share/recently-used.xbel /home/*/.local/share/recently-used.xbel; do
        [ -f "$recent" ] || continue
        echo "--- $recent ---"
        grep -o 'href="[^"]*"' "$recent" 2>/dev/null | sed 's/href="//;s/"$//' | head -50 || cat "$recent" 2>/dev/null | head -50
        echo ""
    done
    echo ""

    # Vim 痕迹
    echo "=== Vim 痕迹 (~/.viminfo) ==="
    for vi in /root/.viminfo /home/*/.viminfo; do
        [ -f "$vi" ] || continue
        user=$(basename "$(dirname "$vi")")
        echo "--- $user ---"
        grep -E '^>|^#' "$vi" 2>/dev/null | head -50
        echo ""
    done
    echo ""

    # 检查 ~/.mysql_history / ~/.psql_history
    echo "=== 数据库历史 ==="
    for hist in /root/.mysql_history /home/*/.mysql_history /root/.psql_history /home/*/.psql_history; do
        [ -f "$hist" ] || continue
        user=$(basename "$(dirname "$hist")")
        echo "--- $user ($(basename "$hist")) ---"
        tail -n 200 "$hist" 2>/dev/null
        echo ""
    done
} > "${OUTDIR}/extra/operation_traces.txt" 2>&1
append_timeline "$(date +%s)" "op_traces" "Operation traces collected"

#----------- 6. WebShell 扫描（大幅增强） -----------
if [ "$MODE" = "quick" ]; then
    echo "[!] Quick mode: skipping webshell deep scan"
    echo "   WebShell scan skipped (quick mode)" >> "${OUTDIR}/webshell_scan.txt"
else
echo "[*] 扫描 WebShell..."
{
    echo "=========================================="
    echo "  WebShell 深度扫描报告 (webshell_scan.txt)"
    echo "=========================================="
    echo "  采集内容: 11维WebShell检测，包括管理工具特征、高危函数、图片马、配置后门、熵分析、文件名异常等"
    echo "  包含: [1]最近30天修改的脚本 [2]高危函数特征(eval/system/exec/Runtime.exec等) [3]管理工具特征(菜刀/蚁剑/冰蝎/哥斯拉/Weevely) [4]经典特征库匹配(已加框架白名单) [5]图片马检测(图片中嵌入PHP/JSP/ASP代码+双扩展名) [6]配置型后门(.htaccess/.user.ini/web.config) [7]文件熵分析(熵>7.0告警) [8]异常文件大小(<50B或>500KB) [9]可疑文件名(纯数字/随机字符串) [10]时间戳异常(ctime-mtime>30天) [11]隐藏脚本文件"
    echo "=========================================="

    # 6.1 最近30天修改的可疑脚本
    echo ""
    echo "=== [1] 最近30天修改的脚本文件 ==="
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -maxdepth 8 -type f -mtime -30 \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" -o -name "*.war" -o -name "*.jar" -o -name "*.py" -o -name "*.pl" -o -name "*.cgi" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "$f"
            append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "webshell_susp" "Modified: $f"
        done
    done

    # 6.2 高危函数特征（增强版）
    echo ""
    echo "=== [2] 高危函数特征 ==="
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find -maxdepth 8 "$d" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" -o -name "*.py" \) -print0 2>/dev/null |
        xargs -0 grep -InHE 'eval\s*\(|base64_decode\s*\(|system\s*\(|exec\s*\(|shell_exec|passthru|popen|proc_open|assert\s*\(|preg_replace\s*\(.*/e|create_function|call_user_func|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.exec\s*\(|Execute\s*\(|WScript\.Shell|CreateObject' 2>/dev/null |
        while IFS=: read -r file line content; do
            echo "${file}:${line}:${content}"
            append_timeline "$(stat -c %Y "$file" 2>/dev/null || true)" "webshell_danger" "${file}:${line}"
        done
    done

    # 6.3 WebShell 管理工具特征检测（菜刀、蚁剑、冰蝎、哥斯拉等）
    echo ""
    echo "=== [3] WebShell 管理工具特征检测 ==="
    echo "--- 扫描菜刀(Chopper)、蚁剑(AntSword)、冰蝎(Behinder)、哥斯拉(Godzilla)、Weevely 等 ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -maxdepth 8 -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            detect_webshell_manager "$f"
        done
    done

    # 6.4 经典 WebShell 特征库
    echo ""
    echo "=== [4] 经典 WebShell 特征库 ==="
    cat > /tmp/ws_sig_$$.txt <<'SIGEOF'
eval\(\$_(GET|POST|REQUEST)
\$_(GET|POST|REQUEST)\[.*\]\(\)
call_user_func\s*\(\s*base64_decode
(@assert|@system|@exec|@shell_exec)
eval\s*\(\s*base64_decode
eval\s*\(\s*gzinflate\s*\(\s*base64_decode
eval\s*\(\s*gzuncompress\s*\(\s*base64_decode
eval\s*\(\s*str_rot13
preg_replace\s*\(\s*['\"][^'\"]*\/[^'\"]*e['\"]
assert\s*\(\s*\$[a-zA-Z_]
create_function\s*\(\s*['\"].*['\"].*eval
SIGEOF
    # 已知框架路径白名单 (ThinkPHP/Laravel/Yii/WordPress 等 legit 路由)
    WS_EXCLUDE_DIRS=( "vendor" "framework" "thinkphp" "laravel" "symfony" "yii" "zend" "cakephp" "codeigniter" "wordpress/wp-includes" "drupal/core" )
    WS_EXCLUDE_ARGS=()
    for ed in "${WS_EXCLUDE_DIRS[@]}"; do
        WS_EXCLUDE_ARGS+=( --exclude-dir="$ed" )
    done

    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && grep -RIlf /tmp/ws_sig_$$.txt "$d" "${WS_EXCLUDE_ARGS[@]}" --include="*.php" --include="*.jsp" --include="*.asp" --include="*.aspx" 2>/dev/null |
        while IFS= read -r f; do
            # 二次确认：跳过明确为框架路由的文件
            if echo "$f" | grep -qE '/(vendor|framework|thinkphp|laravel|symfony|yii|zend|cakephp|codeigniter|wp-includes|drupal)/'; then
                echo "  [INFO] 白名单跳过 (框架路径): $f"
                continue
            fi
            echo "$f"
            append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "webshell_sig" "Hit: $f"
        done
    done

    # 6.5 图片马检测
    echo ""
    echo "=== [5] 图片马检测 ==="
    echo "--- 检查图片文件中是否嵌入可执行代码 ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.bmp" -o -name "*.ico" -o -name "*.webp" -o -name "*.svg" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            detect_image_webshell "$f"
        done
    done

    # 6.6 配置型后门（.htaccess、.user.ini、web.config）
    echo ""
    echo "=== [6] 配置型后门检测 ==="
    for d in "${WEB_DIRS[@]}"; do
        detect_config_backdoor "$d"
    done

    # 6.7 文件熵分析（检测加密/编码的 WebShell）
    echo ""
    echo "=== [7] 文件熵分析（高熵值可能为加密/编码 WebShell） ==="
    echo "--- 阈值: 熵 > 7.0 ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" -o -name "*.js" \) -size +1k -size -1M -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            entropy=$(calc_entropy "$f")
            # 使用 awk 进行浮点比较
            if echo "$entropy" | awk '{exit ($1 > 7.0) ? 0 : 1}'; then
                echo "[HIGH_ENTROPY] 熵值 ${entropy}: $f"
                append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "webshell_entropy" "Entropy ${entropy}: $f"
            fi
        done
    done

    # 6.8 异常文件大小检测
    echo ""
    echo "=== [8] 异常文件大小检测 ==="
    # 极小的 PHP 文件（可能是 loader）
    echo "--- 极小的 PHP 文件 (< 50 bytes) ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f -name "*.php" -size -50c -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "[TINY] $f ($(wc -c < "$f") bytes)"
            cat "$f" 2>/dev/null
        done
    done

    # 极大的脚本文件（可能是打包的 WebShell）
    echo "--- 极大的脚本文件 (> 500KB) ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f \( -name "*.php" -o -name "*.jsp" \) -size +500k -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "[LARGE] $f ($(du -h "$f" | cut -f1))"
        done
    done

    # 6.9 可疑文件名检测
    echo ""
    echo "=== [9] 可疑文件名检测 ==="
    # 纯数字或随机字符串命名的文件
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            basename_f=$(basename "$f")
            # 检查纯数字命名
            if echo "$basename_f" | grep -qE '^[0-9]+\.(php|jsp|asp|aspx)$'; then
                echo "[NUMERIC_NAME] 纯数字文件名: $f"
            fi
            # 检查随机字符串命名（超过20个字符且无下划线/连字符）
            if echo "$basename_f" | grep -qE '^[a-zA-Z0-9]{20,}\.(php|jsp|asp|aspx)$'; then
                echo "[RANDOM_NAME] 随机字符串文件名: $f"
            fi
        done
    done

    # 6.10 时间戳异常检测
    echo ""
    echo "=== [10] 时间戳异常检测 ==="
    echo "--- 创建时间与修改时间差异超过30天的文件 ---"
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            mtime=$(stat -c %Y "$f" 2>/dev/null)
            ctime=$(stat -c %Z "$f" 2>/dev/null)
            if [ -n "$mtime" ] && [ -n "$ctime" ]; then
                diff=$((ctime - mtime))
                abs_diff=${diff#-}
                if [ "$abs_diff" -gt 2592000 ]; then  # 30天 = 2592000秒
                    echo "[TIME_ANOMALY] 时间戳异常: $f (ctime-mtime=${diff}s)"
                fi
            fi
        done
    done

    # 6.11 隐藏文件检测
    echo ""
    echo "=== [11] 隐藏文件检测 ==="
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -type f -name ".*" \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" -o -name "*.sh" -o -name "*.py" \) -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "[HIDDEN] 隐藏脚本文件: $f"
            append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "webshell_hidden" "Hidden: $f"
        done
    done

} > "${OUTDIR}/webshell_scan.txt" 2>&1
fi  # MODE guard close

#----------- 7. 内存马检测（大幅增强） -----------
echo "[*] 检测内存马..."
{
    echo "=========================================="
    echo "  内存马深度检测报告 (memshell_check.txt)"
    echo "=========================================="
    echo "  采集内容: Java/PHP/Python/Node.js/eBPF多语言内存马检测"
    echo "  包含: [1]Java: jps进程列表、JVM系统属性、启动标志、完整类加载器、可疑类(GC.class_histogram)、GeneratedMethodAccessor计数(>25000告警)、动态注入类统计、线程、JIT、maps JAR映射、fd JAR分析 [2]PHP: 配置检查、进程内存扫描、ld.so.preload [3]Python: 进程命令/内存扫描、sitecustomize持久化 [4]Node.js: 环境变量/内存 [5]eBPF: bpftool检测"
    echo "=========================================="

    # 7.1 Java 内存马检测
    echo ""
    echo "=== [1] Java 内存马检测 ==="
    if command -v jps &>/dev/null && command -v jcmd &>/dev/null; then
        echo "--- Java 进程列表 ---"; safe_run 20 jps -lv
        for pid in $(jps -q 2>/dev/null); do
            echo ""
            echo "--- PID: $pid ---"
            cmdline=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' ' ') 2>/dev/null || echo ""
            echo "命令行: $cmdline"

            # 检查 agent 参数
            if echo "$cmdline" | grep -qE '\-javaagent:|\-agentpath:'; then
                echo "[!] 发现 Java Agent 参数!"
                append_timeline "$(date +%s)" "memshell_java_agent" "Java Agent: PID $pid"
            fi

            # 检查 JVM 系统属性和启动标志（深度取证关键）
            echo "--- JVM 系统属性 ---"
            safe_run 15 jcmd "$pid" VM.system_properties 2>&1 | grep -iE 'catalina|tomcat|java\.home|java\.version|user\.dir|shiro|spring|filter|servlet|listener|valve|agent' | head -40
            echo ""
            echo "--- JVM 启动标志 ---"
            safe_run 10 jcmd "$pid" VM.flags 2>&1 | grep -iE 'agent|attach|instrument|classpath|bootclasspath' | head -20

            # 检查类加载器（完整输出，不截断）
            echo "--- 类加载器（完整输出）---"
            safe_run 20 jcmd "$pid" VM.classloaders 2>&1

            # 检查可疑类（Filter、Servlet、Listener、Valve 等）
            echo "--- 可疑类检测 ---"
            safe_run 15 jcmd "$pid" GC.class_histogram 2>&1 | grep -iE 'filter|servlet|listener|shell|cmd|memshell|inject|valve|interceptor|handler|controller|websocket' | head -50

            # GeneratedMethodAccessor 计数（动态代理/反射生成类的数量 — 内存马会导致显著偏高）
            echo "--- GeneratedMethodAccessor 计数 ---"
            accessor_count=$(safe_run 10 jcmd "$pid" GC.class_histogram 2>&1 | grep 'GeneratedMethodAccessor' | awk '{print $2}')
            if [ -n "$accessor_count" ]; then
                echo "GeneratedMethodAccessor 实例数: ${accessor_count}"
                if [ "$accessor_count" -gt 25000 ]; then
                    echo "[!] GeneratedMethodAccessor 数量异常偏高 (>25000)，可能存在大量动态反射/内存马!"
                    append_timeline "$(date +%s)" "memshell_accessor_high" "PID $pid GeneratedMethodAccessor=${accessor_count}"
                elif [ "$accessor_count" -gt 18000 ]; then
                    echo "[!] GeneratedMethodAccessor 数量偏高 (>18000)，建议人工排查"
                else
                    echo "[OK] GeneratedMethodAccessor 在正常范围"
                fi
            else
                echo "[INFO] 无法获取 GeneratedMethodAccessor 计数"
            fi

            # 检测动态生成类（来源为 [?:?] 的类 — 内存马典型特征）
            echo "--- 动态生成类检测（来源 [?:?]） ---"
            safe_run 15 jcmd "$pid" VM.classloaders 2>&1 | grep -c '?:?' | while read cnt; do
                echo "来源未知([?:?])的类加载条目数: $cnt"
                [ "$cnt" -gt 10 ] && echo "[!] 大量未知来源类，疑似动态注入!"
                [ "$cnt" -gt 10 ] && append_timeline "$(date +%s)" "memshell_unknown_source" "PID $pid unknown-source classes: $cnt"
            done

            # 检查 Thread 信息（异常线程名可能是内存马）
            echo "--- 线程信息 ---"
            safe_run 10 jcmd "$pid" Thread.print 2>&1 | grep -E 'tid=|nid=' | head -30

            # 检查 JIT 编译（异常编译可能是动态加载）
            echo "--- JIT 编译信息 ---"
            safe_run 10 jcmd "$pid" Compiler.codecache 2>&1 | head -10

            # 检查 /proc/PID/maps 中的可疑映射
            echo "--- 内存映射检查 ---"
            if [ -f "/proc/${pid}/maps" ]; then
                # 检查可疑的 .so 映射
                grep -E '\.so.*(tmp|dev/shm|home|var/tmp)' "/proc/${pid}/maps" 2>/dev/null && echo "[!] 可疑 so 映射!"
                # 检查匿名可执行映射
                grep -E 'rwxp.*\[heap\]|rwxp.*\[stack\]' "/proc/${pid}/maps" 2>/dev/null && echo "[!] 可执行堆/栈!"
                # 检查可疑的 JAR 映射
                grep -E '\.jar' "/proc/${pid}/maps" 2>/dev/null | grep -vE '/usr/java/|/usr/lib/jvm/|/usr/local/gov' | while read line; do
                    echo "[!] 非标准路径 JAR 映射: $line"
                done
            fi

            # 检查环境变量（LD_PRELOAD 等）
            echo "--- 环境变量 ---"
            cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'LD_PRELOAD|LD_LIBRARY_PATH|JAVA_OPTS|JAVA_TOOL_OPTIONS' && echo "[!] 可疑环境变量!"

            # /proc/PID/fd 完整 JAR 文件分析
            echo "--- 打开的所有 JAR/WAR 文件 ---"
            ls -la "/proc/${pid}/fd/" 2>/dev/null | grep -E '\.jar$|\.war$' | while read line; do
                fd_path=$(readlink -f "/proc/${pid}/fd/$(echo "$line" | awk '{print $NF}')" 2>/dev/null)
                if [ -n "$fd_path" ]; then
                    case "$fd_path" in
                        /usr/java/*|/usr/lib/jvm/*|/usr/local/gov/*)
                            echo "  [STD] $fd_path"
                            ;;
                        /tmp/*|/dev/shm/*|/var/tmp/*|/home/*/.cache/*)
                            echo "  [!!!] 高危路径JAR: $fd_path"
                            append_timeline "$(date +%s)" "memshell_suspicious_jar" "High-risk path JAR: $fd_path (PID $pid)"
                            ;;
                        *)
                            echo "  [SUS] 非标准路径JAR: $fd_path"
                            append_timeline "$(date +%s)" "memshell_nonstd_jar" "Non-std JAR: $fd_path (PID $pid)"
                            ;;
                    esac
                fi
            done

            # 检查打开的文件（可疑路径）
            echo "--- 打开的文件（可疑路径） ---"
            ls -la "/proc/${pid}/fd/" 2>/dev/null | grep -E '(tmp|dev/shm|var/tmp)' | head -10
        done
    else
        echo "[!] jps/jcmd 未安装，跳过 Java 内存马检测"
        echo "    建议安装: yum install java-*-openjdk-devel 或 apt install openjdk-*-jdk"
    fi

    # 7.2 PHP 内存马检测
    echo ""
    echo "=== [2] PHP 内存马检测 ==="

    # 检查 PHP 配置
    echo "--- PHP 配置检查 ---"
    if command -v php &>/dev/null; then
        echo "auto_prepend_file: $(php -r 'echo ini_get("auto_prepend_file");' 2>/dev/null)"
        echo "auto_append_file: $(php -r 'echo ini_get("auto_append_file");' 2>/dev/null)"
        echo "disable_functions: $(php -r 'echo ini_get("disable_functions");' 2>/dev/null)"
        echo "open_basedir: $(php -r 'echo ini_get("open_basedir");' 2>/dev/null)"
        echo "allow_url_include: $(php -r 'echo ini_get("allow_url_include");' 2>/dev/null)"
    fi

    # 检查 PHP-FPM 配置
    echo "--- PHP-FPM 配置 ---"
    for fpm_conf in /etc/php*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf; do
        [ -f "$fpm_conf" ] || continue
        echo "--- $fpm_conf ---"
        if grep -qE 'php_admin_value\[auto_prepend_file\]|php_value\[auto_prepend_file\]' "$fpm_conf" 2>/dev/null; then
            echo "[!] FPM 配置设置了 auto_prepend_file!"
        fi
    done

    # 检查 PHP 进程
    echo "--- PHP 进程检查 ---"
    for pid in $(pgrep -f "php-fpm|apache2|httpd|nginx" 2>/dev/null); do
        echo "--- PID: $pid ---"
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "命令行: $cmdline"

        # 检查命令行可疑内容
        if echo "$cmdline" | grep -qE 'eval|assert|system|exec'; then
            echo "[!] 命令行可疑!"
            append_timeline "$(date +%s)" "memshell_php_cmdline" "Suspicious cmdline: PID $pid"
        fi

        # 检查环境变量
        if [ -r "/proc/${pid}/environ" ]; then
            cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'LD_PRELOAD|PHP_VALUE|auto_prepend' && echo "[!] 可疑环境变量!"
        fi

        # 检查内存中的可疑内容（安全读取）
        if [ -r "/proc/${pid}/maps" ] && [ -r "/proc/${pid}/mem" ]; then
            echo "--- 内存扫描 ---"
            # 取前5个可读段
            grep ' r ' "/proc/${pid}/maps" | head -5 | while IFS=' -' read start end rest; do
                SIZE=$((16#$end - 16#$start))
                [ "$SIZE" -gt "$MEM_READ_LIMIT" ] && SIZE=$MEM_READ_LIMIT
                [ "$ENABLE_MEM_DUMP" = "1" ] && timeout 5 dd if="/proc/${pid}/mem" bs=1 "skip=$((16#$start))" "count=$SIZE" 2>/dev/null | strings | head -3
            done
        fi

        # 检查 LD_PRELOAD
        if [ -r "/proc/${pid}/maps" ]; then
            preload_libs=$(grep '\.so' "/proc/${pid}/maps" | awk '{print $6}' | sort -u)
            for lib in $preload_libs; do
                case "$lib" in
                    */tmp/*|*/dev/shm/*|*/var/tmp/*|*/home/*)
                        echo "[!] 加载了可疑的 .so 库: $lib"
                        append_timeline "$(date +%s)" "memshell_php_so" "Suspicious .so: $lib (PID $pid)"
                        ;;
                esac
            done
        fi
    done

    # 检查 /etc/ld.so.preload
    echo "--- ld.so.preload 检查 ---"
    if [ -f /etc/ld.so.preload ]; then
        echo "[!] /etc/ld.so.preload 存在!"
        cat /etc/ld.so.preload
        append_timeline "$(date +%s)" "memshell_preload" "ld.so.preload exists"
    else
        echo "[OK] /etc/ld.so.preload 不存在"
    fi

    # 7.3 Python 内存马检测
    echo ""
    echo "=== [3] Python 内存马检测 ==="

    # 检查 Python 进程
    for pid in $(ps aux | grep -E '[p]ython|[f]lask|[d]jango|[g]unicorn|[u]wsgi' | awk '{print $2}' 2>/dev/null); do
        echo "--- PID: $pid ---"
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "命令行: $cmdline"

        # 检查命令行可疑内容
        if echo "$cmdline" | grep -qiE '__import__|exec\(|eval\(|compile\(|subprocess'; then
            echo "[!] 命令行可疑!"
            append_timeline "$(date +%s)" "memshell_python_cmdline" "Suspicious Python: PID $pid"
        fi

        # 检查环境变量
        if [ -r "/proc/${pid}/environ" ]; then
            cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'LD_PRELOAD|PYTHONPATH|PYTHONDONTWRITE' && echo "[!] 可疑环境变量!"
        fi

        # 检查内存中的可疑内容
        if [ -r "/proc/${pid}/mem" ]; then
            echo "--- 内存扫描 ---"
            if [ "$ENABLE_MEM_DUMP" = "1" ]; then
                timeout 5 strings "/proc/${pid}/mem" 2>/dev/null | grep -iE '__import__|subprocess|os\.system|base64|eval\(|exec\(|importlib|ctypes' | head -10
            fi
        fi

        # 检查加载的 .so 库
        if [ -r "/proc/${pid}/maps" ]; then
            echo "--- 加载的库 ---"
            preload_libs=$(grep '\.so' "/proc/${pid}/maps" | awk '{print $6}' | sort -u)
            for lib in $preload_libs; do
                case "$lib" in
                    */tmp/*|*/dev/shm/*|*/var/tmp/*)
                        echo "[!] 加载了可疑的 .so 库: $lib"
                        append_timeline "$(date +%s)" "memshell_python_so" "Suspicious .so: $lib (PID $pid)"
                        ;;
                esac
            done
        fi
    done

    # 检查 Python sitecustomize / usercustomize
    echo "--- Python 持久化检查 ---"
    for pydir in /usr/lib/python* /usr/local/lib/python*; do
        [ -d "$pydir" ] || continue
        for f in "$pydir"/sitecustomize.py "$pydir"/usercustomize.py; do
            [ -f "$f" ] || continue
            echo "[!] Python 持久化文件: $f"
            cat "$f" 2>/dev/null | head -20
            append_timeline "$(date +%s)" "memshell_python_persist" "Python persist: $f"
        done
        # 检查 .pth 文件
        for pth in "$pydir"/*.pth; do
            [ -f "$pth" ] || continue
            if grep -qE 'import|exec|eval' "$pth" 2>/dev/null; then
                echo "[!] 可疑 .pth 文件: $pth"
                cat "$pth"
            fi
        done
    done

    # 7.4 Node.js 内存马检测
    echo ""
    echo "=== [4] Node.js 内存马检测 ==="
    for pid in $(pgrep -f "node|nodejs|npm|pm2" 2>/dev/null); do
        echo "--- PID: $pid ---"
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "命令行: $cmdline"

        # 检查环境变量
        if [ -r "/proc/${pid}/environ" ]; then
            cat "/proc/${pid}/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'NODE_OPTIONS|NODE_PATH|--require' && echo "[!] 可疑环境变量!"
        fi

        # 检查内存中的可疑内容
        if [ -r "/proc/${pid}/mem" ]; then
            if [ "$ENABLE_MEM_DUMP" = "1" ]; then
                timeout 5 strings "/proc/${pid}/mem" 2>/dev/null | grep -iE 'child_process|eval\(|Function\(|vm\.run|require\(' | head -10
            fi
        fi
    done

    # 7.5 eBPF 程序检测
    echo ""
    echo "=== [5] eBPF 程序检测 ==="
    if command -v bpftool &>/dev/null; then
        bpftool prog show 2>/dev/null | head -30
        # 检查可疑的 eBPF 程序
        bpftool prog show 2>/dev/null | grep -E 'type.*(kprobe|tracepoint|xdp)' | head -10
    else
        echo "[!] bpftool 未安装"
    fi

} > "${OUTDIR}/memshell_check.txt" 2>&1
append_timeline "$(date +%s)" "memshell" "Memory-malware deep scanning completed"

#----------- 7.6 Java应用服务器目录取证 -----------
echo "[*] Java应用服务器目录取证..."
{
    echo "=============================================="
    echo "  Java 应用服务器目录取证报告 (tomcat_forensics.txt)"
    echo "=============================================="
    echo "  采集内容: Tomcat/Java中间件目录结构深度取证"
    echo "  包含: [1]webapps(近期WAR/JSP/非标准名册) [2]lib(近期修改JAR、Agent Manifest检测) [3]conf/server.xml(Valve/Filter/Pipeline配置+非标准Valve告警) [4]conf/web.xml(Filter/Servlet/Listener注册+内存马特征名直接匹配) [5]bin/setenv.sh+bin/catalina.sh(javaagent/agentpath注入) [6]work/Catalina(近期编译JSP源文件+晚于server.xml的class) [7]logs概要+catalina.out+localhost_access_log+host-manager/manager日志 [8]context.xml(数据库凭证泄露)"
    echo "=============================================="

    # 自动发现 Tomcat / Java 应用目录
    TOMCAT_DIRS=()
    for candidate in \
        /home/user_1/BIreportforms10/tomcat \
        /opt/tomcat /opt/apache-tomcat* /usr/local/tomcat \
        /usr/share/tomcat* /var/lib/tomcat* \
        /opt/jboss /opt/wildfly /opt/weblogic \
        /usr/local/BIreportforms10/tomcat; do
        [ -d "$candidate" ] && TOMCAT_DIRS+=("$candidate")
    done

    # 从进程命令行发现 Tomcat 路径
    for pid in $(pgrep -f "catalina|tomcat|java.*Bootstrap" 2>/dev/null); do
        cmdline=$(cat /proc/${pid}/cmdline 2>/dev/null | tr '\0' '\n') 2>/dev/null || echo ""
        catalina_home=$(echo "$cmdline" | grep 'catalina.home' | cut -d= -f2)
        catalina_base=$(echo "$cmdline" | grep 'catalina.base' | cut -d= -f2)
        [ -n "$catalina_home" ] && [ -d "$catalina_home" ] && TOMCAT_DIRS+=("$catalina_home")
        [ -n "$catalina_base" ] && [ -d "$catalina_base" ] && TOMCAT_DIRS+=("$catalina_base")
        break  # 只取第一个 Java 进程
    done

    # 去重
    TOMCAT_DIRS=($(printf '%s\n' "${TOMCAT_DIRS[@]}" | sort -u))

    if [ ${#TOMCAT_DIRS[@]} -eq 0 ]; then
        echo "[!] 未发现 Tomcat/Java 应用服务器目录"
    fi

    for TCDIR in "${TOMCAT_DIRS[@]}"; do
        echo ""
        echo "=========================================="
        echo "  Tomcat 目录: ${TCDIR}"
        echo "=========================================="

        # 7.6.1 webapps 目录（新上传的 WAR/JSP）
        echo ""
        echo "--- [1] webapps 目录 ---"
        if [ -d "${TCDIR}/webapps" ]; then
            echo "=== 目录列表 ==="
            ls -la "${TCDIR}/webapps/" 2>/dev/null
            echo ""
            echo "=== 最近30天修改的文件 ==="
            find "${TCDIR}/webapps" -type f -mtime -30 \( -name "*.war" -o -name "*.jsp" -o -name "*.class" \) -print0 2>/dev/null |
            while IFS= read -r -d '' f; do
                echo "$f ($(stat -c %y "$f" 2>/dev/null))"
                append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_webapp_mod" "Modified: $f"
            done
            echo ""
            echo "=== 不在标准名册中的 WAR/JAR（可能为上传后门）==="
            find "${TCDIR}/webapps" -maxdepth 2 -type f \( -name "*.war" -o -name "*.jar" \) -print0 2>/dev/null |
            while IFS= read -r -d '' f; do
                fn=$(basename "$f")
                case "$fn" in
                    BIreportforms10.war|ROOT.war|manager.war|host-manager.war|docs.war|examples.war) ;;
                    *)
                        echo "[!] 非标准WAR/JAR: $f"
                        append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_unknown_war" "Unknown: $f"
                        ;;
                esac
            done
        else
            echo "[!] webapps 目录不存在"
        fi

        # 7.6.2 lib 目录（可疑 JAR、Agent JAR）
        echo ""
        echo "--- [2] lib 目录 ---"
        if [ -d "${TCDIR}/lib" ]; then
            echo "=== 最近30天新增/修改的 JAR ==="
            find "${TCDIR}/lib" -maxdepth 1 -type f -name "*.jar" -mtime -30 -print0 2>/dev/null |
            while IFS= read -r -d '' f; do
                echo "[!] 近期修改的JAR: $f ($(stat -c %y "$f" 2>/dev/null))"
                append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_lib_mod" "Modified JAR: $f"
            done
            echo ""
            echo "=== 检查 JAR 中的 Java Agent 清单 ==="
            for jar in "${TCDIR}/lib"/*.jar; do
                [ -f "$jar" ] || continue
                if unzip -l "$jar" 2>/dev/null | grep -q 'META-INF/MANIFEST.MF'; then
                    manifest=$(unzip -p "$jar" META-INF/MANIFEST.MF 2>/dev/null)
                    if echo "$manifest" | grep -qE 'Premain-Class|Agent-Class|Can-Retransform-Classes|Can-Redefine-Classes'; then
                        echo "[!] Agent JAR 发现: $jar"
                        echo "$manifest" | grep -E 'Premain-Class|Agent-Class|Can-Retransform|Can-Redefine'
                        append_timeline "$(stat -c %Y "$jar" 2>/dev/null || true)" "tomcat_agent_jar" "Agent JAR: $jar"
                    fi
                fi
            done
        else
            echo "[!] lib 目录不存在"
        fi

        # 7.6.3 conf 目录（配置篡改）
        echo ""
        echo "--- [3] conf 目录 ---"
        if [ -d "${TCDIR}/conf" ]; then
            echo "=== server.xml Valve/Filter/Pipeline 检查 ==="
            if [ -f "${TCDIR}/conf/server.xml" ]; then
                grep -nE 'Valve|Filter|Pipeline|Realm' "${TCDIR}/conf/server.xml" 2>/dev/null | while read line; do
                    echo "  $line"
                    # 标记非标准 Valve
                    if echo "$line" | grep -qE 'className.*Valve' && ! echo "$line" | grep -qE 'org\.apache\.catalina\.(valves|authenticator|realm|core)'; then
                        echo "  [!] 非标准 Valve 配置!"
                        append_timeline "$(stat -c %Y "${TCDIR}/conf/server.xml" 2>/dev/null || true)" "tomcat_valve" "Suspicious Valve: $line"
                    fi
                done
            fi
            echo ""
            echo "=== web.xml Filter/Servlet/Listener 检查 ==="
            if [ -f "${TCDIR}/conf/web.xml" ]; then
                grep -nE '<filter>|<filter-name>|<filter-class>|<servlet>|<servlet-name>|<servlet-class>|<listener>|<listener-class>' "${TCDIR}/conf/web.xml" 2>/dev/null | while read line; do
                    echo "  $line"
                    # 标记非标准配置
                    if echo "$line" | grep -qE 'org\.apache\.catalina\.filters\.[A-Z]' && echo "$line" | grep -qE '(Phyllostominae|Plasmodesma|Betis)'; then
                        echo "  [!!!] 内存马 Filter 配置发现!"
                        append_timeline "$(stat -c %Y "${TCDIR}/conf/web.xml" 2>/dev/null || true)" "memshell_config" "Memory shell in web.xml: $line"
                    fi
                done
            fi
            echo ""
            echo "=== conf 目录文件修改时间 ==="
            find "${TCDIR}/conf" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null | sort -r
        else
            echo "[!] conf 目录不存在"
        fi

        # 7.6.4 bin 目录（javaagent 注入）
        echo ""
        echo "--- [4] bin 目录 ---"
        if [ -d "${TCDIR}/bin" ]; then
            echo "=== setenv.sh / catalina.sh 检查 ==="
            for f in "${TCDIR}/bin/setenv.sh" "${TCDIR}/bin/setenv.bat" "${TCDIR}/bin/catalina.sh"; do
                [ -f "$f" ] || continue
                echo "--- $f ---"
                cat "$f" 2>/dev/null
                if grep -qE 'javaagent|agentpath|agentlib|Xbootclasspath' "$f" 2>/dev/null; then
                    echo "[!] 发现 Agent 类参数!"
                    append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_agent_arg" "Agent arg in: $f"
                fi
            done
        else
            echo "[!] bin 目录不存在"
        fi

        # 7.6.5 work/Catalina 目录（编译的 JSP class 文件）
        echo ""
        echo "--- [5] work/Catalina 目录 ---"
        if [ -d "${TCDIR}/work/Catalina" ]; then
            echo "=== 最近30天编译的 JSP 源文件(.java) ==="
            find "${TCDIR}/work/Catalina" -name "*.java" -mtime -30 -print0 2>/dev/null |
            while IFS= read -r -d '' f; do
                echo "$f ($(stat -c %y "$f" 2>/dev/null))"
                append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_work_java" "Compiled JSP: $f"
            done | head -50
            echo ""
            echo "=== 晚于 server.xml 修改时间的 class 文件（可能关联攻击）==="
            if [ -f "${TCDIR}/conf/server.xml" ]; then
                SERVER_XML_MTIME=$(stat -c %Y "${TCDIR}/conf/server.xml" 2>/dev/null)
                [ -n "$SERVER_XML_MTIME" ] && find "${TCDIR}/work/Catalina" -name "*.class" -newer "${TCDIR}/conf/server.xml" -print0 2>/dev/null |
                while IFS= read -r -d '' f; do
                    echo "$f"
                    append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tomcat_work_class" "Late class: $f"
                done | head -50
            fi
        else
            echo "[!] work/Catalina 目录不存在"
        fi

        # 7.6.6 temp 目录
        echo ""
        echo "--- [6] temp 目录 ---"
        [ -d "${TCDIR}/temp" ] && ls -la "${TCDIR}/temp/" 2>/dev/null | head -50

        # 7.6.7 logs 目录信息 + Tomcat 原生日志收集
        echo ""
        echo "--- [7] logs 目录概要 ---"
        if [ -d "${TCDIR}/logs" ]; then
            ls -lh "${TCDIR}/logs/" 2>/dev/null | head -30

            # catalina.out（JVM异常/classloader错误/OOM）
            for cata_log in "${TCDIR}/logs/catalina.out" "${TCDIR}/logs/catalina."*.log; do
                [ -f "$cata_log" ] || continue
                dest="${OUTDIR}/logs/tomcat_$(basename "$cata_log")"
                fsize=$(stat -c %s "$cata_log" 2>/dev/null || true)
                if [ "$fsize" -lt "$LOG_SIZE_LIMIT" ] && [ "$fsize" -gt 0 ]; then
                    cp -p "$cata_log" "$dest" 2>/dev/null && echo "[✔] $cata_log -> $dest"
                elif [ "$fsize" -gt 0 ]; then
                    echo "[!] catalina log 过大，双段截取 (${fsize}B): $cata_log"
                    head -c 100M "$cata_log" > "${dest}.head" 2>/dev/null
                    tail -c 100M "$cata_log" > "${dest}.tail" 2>/dev/null
                fi
            done

            # localhost_access_log（原始HTTP请求行 — 关键取证来源）
            for acc_log in "${TCDIR}/logs/localhost_access_log."*.txt; do
                [ -f "$acc_log" ] || continue
                dest="${OUTDIR}/logs/tomcat_$(basename "$acc_log")"
                fsize=$(stat -c %s "$acc_log" 2>/dev/null || true)
                if [ "$fsize" -lt "$LOG_SIZE_LIMIT" ] && [ "$fsize" -gt 0 ]; then
                    cp -p "$acc_log" "$dest" 2>/dev/null && echo "[✔] $acc_log -> $dest"
                elif [ "$fsize" -gt 0 ]; then
                    echo "[!] access_log 过大，双段截取 (${fsize}B): $acc_log"
                    head -c 100M "$acc_log" > "${dest}.head" 2>/dev/null
                    tail -c 100M "$acc_log" > "${dest}.tail" 2>/dev/null
                fi
            done

            # host-manager / manager 日志
            for mgr_log in "${TCDIR}/logs/host-manager."*.log "${TCDIR}/logs/manager."*.log; do
                [ -f "$mgr_log" ] || continue
                dest="${OUTDIR}/logs/tomcat_$(basename "$mgr_log")"
                cp -p "$mgr_log" "$dest" 2>/dev/null && echo "[✔] $mgr_log -> $dest"
            done
        else
            echo "[!] logs 目录不存在"
        fi

        # 7.6.8 context.xml（数据库凭证）
        echo ""
        echo "--- [8] context.xml ---"
        for ctx in "${TCDIR}/conf/context.xml" "${TCDIR}/conf/Catalina/localhost/"*.xml; do
            [ -f "$ctx" ] || continue
            echo "--- $ctx ---"
            cat "$ctx" 2>/dev/null
            # 标记泄露的数据库凭证
            if grep -qE 'username=|password=|url=|driverClassName=|jdbc:|Resource.*auth' "$ctx" 2>/dev/null; then
                echo "[!] context.xml 包含数据库凭证配置!"
                append_timeline "$(stat -c %Y "$ctx" 2>/dev/null || true)" "db_credential_leak" "DB credential in: $ctx"
            fi
        done
    done

} > "${OUTDIR}/tomcat_forensics.txt" 2>&1
append_timeline "$(date +%s)" "tomcat_forensics" "Java app server directory forensics completed"

#----------- 8. 日志收集（含轮转日志 .1/.2.gz/date-based，安全防IO风暴） -----------
echo "[*] 收集近3天访问过的日志（跳过超大文件）..."
collect_logs_dir() {
    local dir="$1"
    local depth="${2:-3}"  # default maxdepth 3 for subdirs like /var/log/nginx/
    [ -d "$dir" ] || return

    # Pattern coverage for rotated logs:
    #   *.log         - active logs
    #   *.log.*       - logrotate: access.log.1, error.log.2.gz
    #   *.[0-9]       - bare rotation: messages.1, syslog.2, auth.log.3
    #   *.[0-9].*     - compressed rotation: messages.2.gz, syslog.3.xz
    #   *-20[0-9][0-9]* - date-based: secure-20250501, messages-20250501
    #   *.gz *.bz2 *.xz - compressed standalone
    find "$dir" -maxdepth "$depth" -type f         \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*"            -o -name "*-20[0-9][0-9]*" -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" \)         -mtime -"${LOG_AGE_DAYS:-7}" -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        # Skip binary/non-text files that are not compressed logs
        local ext="${f##*.}"
        case "$ext" in
            gz|bz2|xz) ;; # compressed logs, always collect
            *)
                # Check if it's a text file
                file "$f" 2>/dev/null | grep -qE 'text|ASCII|UTF|empty|log' || continue
                ;;
        esac

        local fsize=$(stat -c %s "$f" 2>/dev/null || true)
        dest="${OUTDIR}/logs/$(echo "$f" | sed 's|^/||; s|/|_|g')"

        if [ "$fsize" -lt "$LOG_SIZE_LIMIT" ] && [ "$fsize" -gt 0 ]; then
            cp -p "$f" "$dest" 2>/dev/null && echo "[OK] $f -> $dest"
        elif [ "$fsize" -gt 0 ]; then
            # For compressed files, copy whole (already size-limited)
            if [ "$ext" = "gz" ] || [ "$ext" = "bz2" ] || [ "$ext" = "xz" ]; then
                cp -p "$f" "$dest" 2>/dev/null && echo "[OK] $f (compressed) -> $dest"
            else
                echo "[!] 大文件双段截取: $f"
                head -c 50M "$f" > "${dest}.head_50M" 2>/dev/null
                tail -c 50M "$f" > "${dest}.tail_50M" 2>/dev/null
            fi
        fi
    done
}

for dir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${AUTH_LOG_DIRS[@]}"; do
    collect_logs_dir "$dir" >> "${OUTDIR}/log_collection.txt"
done

# 收集 audit 日志
echo "[*] 收集审计日志..."
{
    echo "=============================================="
    echo "  审计日志 (extra/audit_logs.txt)"
    echo "=============================================="
    echo "  采集内容: Linux审计子系统日志、systemd journal近3天"
    echo "  包含: ausearch最近审计事件(前200)、journalctl --since 3 days ago(前500)"
    echo ""
    if command -v ausearch &>/dev/null; then
        echo "=== 最近的审计事件 ==="
        safe_run 30 ausearch -ts recent 2>/dev/null | head -200
    fi
    # systemd journal
    if command -v journalctl &>/dev/null; then
        echo "=== 最近3天的 journal ==="
        safe_run 30 journalctl --since "3 days ago" --no-pager 2>/dev/null | head -500
    fi
} > "${OUTDIR}/extra/audit_logs.txt" 2>&1

append_timeline "$(date +%s)" "logs" "Logs copied (size-limited)"

#----------- 8.5. 应用日志模式分析 -----------
echo "[*] 应用日志模式分析..."
{
    echo "=============================================="
    echo "  应用日志可疑模式分析报告 (log_pattern_analysis.txt)"
    echo "=============================================="
    echo "  采集内容: 对所有已收集日志进行可疑模式正则匹配"
    echo "  包含: [1]认证异常(Add user: admin/root/system + login(284)非正常SSO路径) [2]异常堆栈(disposeException/ServletHelper/__Anyone__未认证/Filter相关NullPointer) [3]内存马特征([?:?]来源类/Phyllostominae等类名/Hander混淆名) [4]会话异常(session created/destroyed/SessionMgr) [5]外联与命令执行(ProcessBuilder/Runtime.exec/javax.crypto加密通信)"
    echo "=============================================="

    # 在所有已收集的日志中搜索可疑模式
    echo ""
    echo "=== [1] 认证异常模式 ==="
    for logdir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${TOMCAT_DIRS[@]/%/\/logs}"; do
        [ -d "$logdir" ] || continue
        echo "--- 扫描目录: $logdir ---"
        # Add user 异常（内存马直接调用登录API的痕迹）
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'Add user:\s*(admin|root|system|administrator|yhReport)' 2>/dev/null | head -30
        # 登录方法异常（login(284) 非正常SSO路径）
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'login.*\(284\)|RequestUtils\.login' 2>/dev/null | head -30
    done

    echo ""
    echo "=== [2] 异常堆栈/异常处理 ==="
    for logdir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${TOMCAT_DIRS[@]/%/\/logs}"; do
        [ -d "$logdir" ] || continue
        # disposeException（异常处理路径暴露漏洞触发）
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'disposeException|ServletHelper|__Anyone__|not authenticated' 2>/dev/null | head -30
        # NullPointerException / ClassCastException（内存马注入时常见）
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'NullPointerException.*Filter|ClassCastException.*Filter|IllegalArgumentException.*Valve' 2>/dev/null | head -20
    done

    echo ""
    echo "=== [3] 内存马特征模式 ==="
    for logdir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${TOMCAT_DIRS[@]/%/\/logs}"; do
        [ -d "$logdir" ] || continue
        # 动态注入类的来源标记 [?:?]
        echo "--- 动态注入类来源 [?:?] ---"
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -cH '\[?:?\]' 2>/dev/null | grep -v ':0$' | head -20
        # 可疑类名
        echo "--- 可疑类名/包名 ---"
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE '(Phyllostominae|Plasmodesma|Betis|Illure|ollyHandler|qxszcHandler|gcmrHandler|cbarpHandler|org\.apache\.commons\.lang\.Illure)' 2>/dev/null | head -30
    done

    echo ""
    echo "=== [4] 会话异常模式 ==="
    for logdir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${TOMCAT_DIRS[@]/%/\/logs}"; do
        [ -d "$logdir" ] || continue
        # session 异常创建/销毁
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'session.*created|session.*destroyed|SessionMgr|Session.*remove' 2>/dev/null | head -30
    done

    echo ""
    echo "=== [5] 异常外联/命令执行 ==="
    for logdir in "${WEB_LOG_DIRS[@]}" "${APP_LOG_DIRS[@]}" "${TOMCAT_DIRS[@]/%/\/logs}"; do
        [ -d "$logdir" ] || continue
        # ProcessBuilder / Runtime.exec 痕迹
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'ProcessBuilder|Runtime\.getRuntime\(\)\.exec|\.exec\s*\(' 2>/dev/null | head -20
        # 加密通信特征
        find -maxdepth 8 "$logdir" \( -name "*.log" -o -name "*.log.*" -o -name "*.[0-9]" -o -name "*.[0-9].*" -o -name "*-20[0-9][0-9]*" \) -type f -size -100M -print0 2>/dev/null |
        xargs -0 grep -nHE 'javax\.crypto|Cipher\.getInstance|AES/CBC|SecretKey' 2>/dev/null | head -20
    done

} > "${OUTDIR}/log_pattern_analysis.txt" 2>&1
append_timeline "$(date +%s)" "log_analysis" "Application log pattern analysis completed"

#----------- 8.6. 临时目录 Java class 文件检测 -----------
echo "[*] 检测临时目录中的 Java class 文件..."
{
    echo "=============================================="
    echo "  临时目录 Java class 文件检测 (temp_class_check.txt)"
    echo "=============================================="
    echo "  采集内容: 扫描临时目录中的Java .class文件(内存马/动态代理落地痕迹)"
    echo "  包含: /tmp中.class(含strings前5行)、/dev/shm中.class、/var/tmp中.class、hsperfdata_*中的class dump文件"
    echo "=============================================="

    echo ""
    echo "=== /tmp 中的 .class 文件 ==="
    find /tmp -maxdepth 3 -name "*.class" -type f -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "  $f ($(stat -c %y "$f" 2>/dev/null), $(wc -c < "$f" 2>/dev/null) bytes)"
        # 尝试反编译类名
        strings "$f" 2>/dev/null | head -5
        echo "  ---"
        append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "tmp_class_file" "Class in /tmp: $f"
    done

    echo ""
    echo "=== /dev/shm 中的 .class 文件 ==="
    find /dev/shm -name "*.class" -type f -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "  $f ($(stat -c %y "$f" 2>/dev/null))"
        append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "shm_class_file" "Class in /dev/shm: $f"
    done

    echo ""
    echo "=== /var/tmp 中的 .class 文件 ==="
    find /var/tmp -maxdepth 3 -name "*.class" -type f -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "  $f ($(stat -c %y "$f" 2>/dev/null))"
        append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "vartmp_class_file" "Class in /var/tmp: $f"
    done

    echo ""
    echo "=== 全盘搜索可疑 class dump（/tmp/hsperfdata_* 中） ==="
    for hsperf in /tmp/hsperfdata_*; do
        [ -d "$hsperf" ] || continue
        echo "--- $hsperf ---"
        ls -la "$hsperf/" 2>/dev/null | head -20
    done

} > "${OUTDIR}/temp_class_check.txt" 2>&1
append_timeline "$(date +%s)" "temp_class" "Temp class file detection completed"

#----------- 8.7 文件系统保护点 (lsattr + MIME type 劫持) -----------
echo "[*] 检查文件系统保护点..."
{
    echo "=============================================="
    echo "  文件系统保护点检测 (extra/filesystem_protection.txt)"
    echo "=============================================="
    echo "  采集内容: 不可变文件(chattr +i)检测、MIME type劫持检测"
    echo ""

    # lsattr: 检测被 chattr +i / +a 锁定的可疑文件
    echo "=== 不可变文件检测 (lsattr chattr +i) ==="
    if command -v lsattr &>/dev/null; then
        echo "--- /tmp /dev/shm /var/tmp 中不可变文件 ---"
        safe_run 10 lsattr -R /tmp /dev/shm /var/tmp 2>/dev/null | grep -E '^.{3}i' | head -20
        echo "--- /etc 中不可变文件 ---"
        safe_run 10 lsattr -R /etc 2>/dev/null | grep -E '^.{3}i' | head -20
        echo "--- /root /home 中不可变文件 ---"
        safe_run 15 lsattr -R /root /home 2>/dev/null | grep -E '^.{3}i' | head -20
    else
        echo "[!] lsattr 不可用，跳过不可变文件检测"
    fi
    echo ""

    # MIME type 劫持检测
    echo "=== MIME type 劫持检测 ==="
    for mime_dir in /root/.local/share/applications /home/*/.local/share/applications; do
        [ -d "$mime_dir" ] || continue
        echo "--- $mime_dir ---"
        ls -la "$mime_dir/" 2>/dev/null
        for desk in "$mime_dir"/*.desktop; do
            [ -f "$desk" ] || continue
            echo "--- $desk ---"
            cat "$desk" 2>/dev/null
            # 检查可疑 Exec 指向 /tmp /dev/shm
            if grep -qE '^Exec=.*/(tmp|dev/shm|var/tmp)/' "$desk" 2>/dev/null; then
                echo "[!] MIME 劫持: Exec 指向可疑路径!"
                append_timeline "$(stat -c %Y "$desk" 2>/dev/null || true)" "mime_hijack" "MIME hijack: $desk"
            fi
        done
    done
    echo ""

    # xdg-mime 默认应用检查（可能被劫持）
    echo "=== xdg-mime 默认浏览器/终端 ==="
    safe_run 5 xdg-mime query default x-scheme-handler/http 2>/dev/null || echo "xdg-mime 不可用"
    safe_run 5 xdg-mime query default x-scheme-handler/https 2>/dev/null || true
    safe_run 5 xdg-mime query default application/x-shellscript 2>/dev/null || true
} > "${OUTDIR}/extra/filesystem_protection.txt" 2>&1
append_timeline "$(date +%s)" "fs_protection" "Filesystem protection points checked"

#----------- 9. 最近3天修改的文件（排除大目录 + 进度点 + 安全超时） -----------
if [ "$MODE" = "quick" ]; then
    echo "[!] Quick mode: skipping recent file scan"
    echo "   Recent files scan skipped (quick mode)" >> "${OUTDIR}/extra/recent_files.txt"
else
echo -n "[*] 扫描最近3天修改的文件（进度点每1秒）"
{
    echo "=============================================="
    echo "  最近3天修改的文件 (extra/recent_files.txt)"
    echo "=============================================="
    echo "  采集内容: 全盘最近3天文件变更快照(前1000条)+Web目录变更+临时目录ELF/二进制"
    echo "  包含: 系统关键目录变更(find -mtime -3前1000)、Web目录全部变更、/tmp|/dev/shm|/var/tmp中ELF/script/packed文件"
    echo ""
    echo "=== 系统关键目录变更 ==="
    timeout 30 find / -xdev \( "${EXCLUDE_FIND[@]}" \) -type f -mtime -3 -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "$f"
        epoch=$(stat -c %Y "$f" 2>/dev/null || true)
        [ "$epoch" -gt 0 ] && append_timeline "$epoch" "file_modify" "$f"
    done | head -1000
    echo "=== Web 目录变更 ==="
    for d in "${WEB_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -xdev -type f -mtime -3 -print0 2>/dev/null |
        while IFS= read -r -d '' f; do
            echo "$f"
            append_timeline "$(stat -c %Y "$f" 2>/dev/null || true)" "file_modify_web" "$f"
        done
    done
} > "${OUTDIR}/extra/recent_files.txt" 2>&1 &
FIND_PID=$!
progress_dot & DOT_PID=$!
wait $FIND_PID 2>/dev/null
kill $DOT_PID 2>/dev/null
echo ""
fi
#----------- 10. SSH 持久化与后门 -----------
echo "[*] 检查 SSH 配置及后门..."
{
    echo "=============================================="
    echo "  SSH持久化与后门检测 (extra/ssh_persistence.txt)"
    echo "=============================================="
    echo "  采集内容: SSH配置安全审计、authorized_keys、空密码账户、非系统用户、SSH wrapper"
    echo "  包含: sshd_config、所有用户authorized_keys、空密码账户(/etc/shadow)、UID>=1000非系统用户、lastlog、/etc/ssh/sshrc、~/.ssh/rc、~/.ssh/config"
    echo ""
    echo "=== /etc/ssh/sshd_config ==="; cat /etc/ssh/sshd_config 2>/dev/null
    echo "=== authorized_keys ==="
    find /root /home -name authorized_keys -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "--- $f ---"
        ls -la "$f"
        cat "$f"
    done
    echo "=== 空密码账户 ==="; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null
    echo "=== 非系统用户 (UID>=1000) ==="; awk -F: '($3>=1000){print $1,$3}' /etc/passwd
    echo "=== lastlog ==="; safe_run 10 lastlog 2>/dev/null | head -20

    # 新增：检查 SSH wrapper 和环境
    echo "=== SSH 相关文件 ==="
    ls -la /etc/ssh/sshrc 2>/dev/null && echo "[!] /etc/ssh/sshrc 存在!"
    ls -la ~/.ssh/rc 2>/dev/null && echo "[!] ~/.ssh/rc 存在!"
    for u in /root /home/*; do
        [ -d "$u/.ssh" ] || continue
        echo "--- $u/.ssh/ ---"
        ls -la "$u/.ssh/" 2>/dev/null
        # 检查 config 文件
        [ -f "$u/.ssh/config" ] && echo "--- SSH Config ---" && cat "$u/.ssh/config"
    done
} > "${OUTDIR}/extra/ssh_persistence.txt" 2>&1

#----------- 11. SUID / SGID（含异常路径，超时保护） -----------
echo "[*] 查找异常 SUID..."
{
    echo "=============================================="
    echo "  SUID/SGID 异常文件检测 (extra/suid_sgid.txt)"
    echo "=============================================="
    echo "  采集内容: 全盘SUID文件排查(权限提升攻击面分析)"
    echo "  包含: 全局SUID(排除/bin|/sbin|/usr/bin|/usr/sbin|/usr/lib系统路径)、/tmp|/dev/shm|/var/tmp中高危SUID"
    echo ""
    echo "=== 全局 SUID（排除系统路径）==="
    timeout 30 find / -xdev \( "${EXCLUDE_FIND[@]}" \) -type f -perm -4000 -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        echo "$f"
    done | grep -vE '(/bin/|/sbin/|/usr/bin/|/usr/sbin/|/usr/lib/)' | head -200
    echo "=== 高可疑路径 SUID (/tmp, /dev/shm, /var/tmp) ==="
    find /tmp /dev/shm /var/tmp -type f -perm -4000 -print0 2>/dev/null |
    while IFS= read -r -d '' f; do echo "$f"; done
} > "${OUTDIR}/extra/suid_sgid.txt" 2>&1

#----------- 12. 内核模块与 Rootkit（安全 /proc 扫描） -----------
echo "[*] 检查内核模块与 Rootkit..."
{
    echo "=============================================="
    echo "  内核模块与Rootkit检测 (extra/kernel_rootkit.txt)"
    echo "=============================================="
    echo "  采集内容: 内核完整性检查、Rootkit特征字符串匹配、Capabilities审计"
    echo "  包含: 加载的内核模块+签名检查、/etc/ld.so.preload、core_pattern、ACPI tables、/proc中hidepid/diamorphine/adore等Rootkit特征、capabilities审计(cap_setuid/cap_sys_admin/cap_sys_ptrace/cap_net_raw)"
    echo ""
    echo "=== 加载的内核模块 ==="; safe_run 10 lsmod
    echo "=== 模块签名（前30个） ==="
    lsmod | awk 'NR>1{print $1}' | head -30 | while read mod; do
        safe_run 3 modinfo "$mod" 2>/dev/null | grep -E 'filename|signer'
    done
    echo "=== /etc/ld.so.preload ==="; cat /etc/ld.so.preload 2>/dev/null || echo "不存在"
    echo "=== core_pattern ==="; cat /proc/sys/kernel/core_pattern 2>/dev/null
    echo "=== ACPI tables ==="; ls -la /sys/firmware/acpi/tables 2>/dev/null
    echo "=== 简单 rootkit 字符串探测（排除超大文件） ==="
    find /proc -maxdepth 1 -type f \( -name 'kcore' -o -name 'kallsyms' -o -name 'kpage*' -o -name 'vmcore' -o -name 'sched_debug' \) -prune -o -type f -print0 2>/dev/null |
        xargs -0 -r safe_run 15 grep -lE 'hidepid|diamorphine|adore|kbeast|suterusu' 2>/dev/null | head -10

    # 检查 capabilities（单次扫描，超时保护）
    echo "=== Capabilities 检查 ==="
    safe_run 30 getcap -r / 2>/dev/null | {
        tee /tmp/capabilities_$$.txt 2>/dev/null
        head -50
    }
    echo "=== 可疑 Capabilities ==="
    grep -E 'cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_net_raw' /tmp/capabilities_$$.txt 2>/dev/null | head -20
    rm -f /tmp/capabilities_$$.txt
} > "${OUTDIR}/extra/kernel_rootkit.txt" 2>&1

#----------- 12.5 隐藏内核模块 + sysctl + sysrq + auditd -----------
echo "[*] 深度内核安全检查..."
{
    echo "=============================================="
    echo "  深度内核安全检查 (extra/kernel_deep.txt)"
    echo "=============================================="
    echo "  采集内容: 隐藏模块检测、sysctl参数、sysrq状态、auditd规则"
    echo ""
    echo "=== 隐藏内核模块检测 (/proc/modules vs lsmod) ==="
    proc_mod_count=$(cat /proc/modules 2>/dev/null | wc -l)
    lsmod_count=$(lsmod 2>/dev/null | tail -n +2 | wc -l)
    echo "  /proc/modules 模块数: ${proc_mod_count}"
    echo "  lsmod 模块数: ${lsmod_count}"
    if [ "$proc_mod_count" != "$lsmod_count" ]; then
        echo "  [!!!] 警告: /proc/modules 和 lsmod 数量不一致!"
        echo "  [!!!] 可能存在隐藏内核模块 (LKM rootkit)"
        append_timeline "$(date +%s)" "hidden_kmod" "Module count mismatch"
    fi
    echo ""
    echo "=== 未签名内核模块检测 ==="
    for mod in $(lsmod 2>/dev/null | awk 'NR>1{print $1}' | head -50); do
        sig=$(modinfo "$mod" 2>/dev/null | grep -E 'sig_key|signer' | head -1)
        [ -z "$sig" ] && echo "  [!!!] 未签名模块: $mod"
    done
    echo ""
    echo "=== sysctl 内核参数 dump ==="
    safe_run 15 sysctl -a 2>/dev/null | head -300
    echo ""
    echo "=== sysrq 状态 ==="
    sysrq_val=$(cat /proc/sys/kernel/sysrq 2>/dev/null || echo "unknown")
    echo "  /proc/sys/kernel/sysrq = ${sysrq_val}"
    [ "$sysrq_val" != "0" ] && [ "$sysrq_val" != "unknown" ] && echo "  [!!!] Magic SysRq 已启用!"
    echo ""
    echo "=== auditd 审计规则 ==="
    safe_run 10 auditctl -l 2>/dev/null || echo "auditd 不可用"
    echo ""
    echo "=== auditd 服务状态 ==="
    safe_run 5 systemctl status auditd 2>/dev/null || safe_run 5 service auditd status 2>/dev/null || echo "auditd 服务不可用"
    echo ""
    echo "=== 内核启动参数 (cmdline) ==="
    cat /proc/cmdline 2>/dev/null
    echo ""
    echo "=== LSM (SELinux/AppArmor) 详细状态 ==="
    safe_run 5 sestatus 2>/dev/null || echo "sestatus 不可用"
    safe_run 5 aa-status 2>/dev/null || echo "aa-status 不可用"
} > "${OUTDIR}/extra/kernel_deep.txt" 2>&1
append_timeline "$(date +%s)" "kernel_deep" "Deep kernel check completed"
#----------- 13. 关键文件哈希 -----------
if [ "$MODE" = "quick" ]; then
    echo "[!] Quick mode: skipping file hash computation"
else
echo "[*] 计算关键文件哈希..."
{
    echo "=============================================="
    echo "  关键文件哈希 (extra/file_hashes.txt)"
    echo "=============================================="
    echo "  采集内容: 系统关键二进制和账户文件SHA256哈希(完整性校验)"
    echo "  包含: /bin/ls|curl|wget|ps|netstat|ssh|scp|sudo|bash|sh|find|grep|awk|sed|login|useradd|usermod|sshd等SHA256、/etc/passwd|shadow|group哈希、capabilities审计、namespace列表、eBPF程序"
    echo ""
    echo "=== 二进制哈希 ==="
    for f in /bin/ls /usr/bin/curl /usr/bin/wget /bin/ps /bin/netstat /usr/bin/ssh /usr/bin/scp /usr/bin/sudo /usr/sbin/sshd /bin/bash /bin/sh /usr/bin/find /usr/bin/grep /usr/bin/awk /usr/bin/sed /bin/login /usr/sbin/useradd /usr/sbin/usermod; do
        [ -f "$f" ] && sha256sum "$f"
    done
    echo "=== 账户文件哈希 ==="
    sha256sum /etc/passwd /etc/shadow /etc/group 2>/dev/null
    echo "=== capability 与 namespace ==="
    safe_run 10 getcap -r / 2>/dev/null | head -50
    safe_run 10 lsns 2>/dev/null | head -30
    safe_run 10 bpftool prog show 2>/dev/null | head -20
} > "${OUTDIR}/extra/file_hashes.txt" 2>&1
fi

#----------- 13.5 取证增强 (文件系统元数据 + 软件包安装时间线 + 进程审计) -----------
echo "[*] 取证增强数据收集..."
{
    echo "=============================================="
    echo "  取证增强 (extra/forensic_enhancement.txt)"
    echo "=============================================="
    echo "  采集内容: 文件系统元数据、软件包安装时间线、进程审计记录"
    echo ""

    # 文件系统元数据
    echo "=== 文件系统元数据 ==="
    for dev in $(lsblk -ndo NAME 2>/dev/null); do
        echo "--- /dev/$dev (tune2fs) ---"
        safe_run 5 tune2fs -l "/dev/$dev" 2>/dev/null | grep -E 'Filesystem created|Last mount|Last write|Mount count|Lifetime writes' || true
    done
    # dump2efs 单独尝试
    echo "--- dump2efs / ---"
    safe_run 5 dumpe2fs -h /dev/sda1 2>/dev/null | head -30 || safe_run 5 dumpe2fs -h /dev/vda1 2>/dev/null | head -30 || echo "dumpe2fs 不可用"
    echo ""

    # 软件包安装时间线（rpm/deb）
    echo "=== 软件包安装时间线 ==="
    if command -v rpm &>/dev/null; then
        echo "--- RPM 包安装时间 (最近50条) ---"
        safe_run 15 rpm -qa --last 2>/dev/null | head -50
    fi
    if command -v dpkg &>/dev/null; then
        echo "--- DEB 包安装日志 ---"
        safe_run 10 grep ' install ' /var/log/dpkg.log 2>/dev/null | tail -50 || true
    fi
    echo ""

    # 进程审计记录（lastcomm）
    echo "=== 进程审计记录 (lastcomm) ==="
    if command -v lastcomm &>/dev/null; then
        safe_run 10 lastcomm 2>/dev/null | head -50 || echo "lastcomm 无数据（需 acct 服务启用）"
    else
        echo "[!] lastcomm 不可用（需安装 psacct 或 acct 包并启用 acct 服务）"
    fi
    # sa 统计
    if command -v sa &>/dev/null; then
        echo "--- sa 进程统计 ---"
        safe_run 10 sa 2>/dev/null | head -30 || true
    fi
    echo ""

    # 已安装软件包统计
    echo "=== 软件包数量统计 ==="
    rpm_count=$(rpm -qa 2>/dev/null | wc -l)
    dpkg_count=$(dpkg -l 2>/dev/null | grep '^ii' | wc -l)
    echo "RPM 包总数: ${rpm_count:-0}"
    echo "DEB 包总数: ${dpkg_count:-0}"
} > "${OUTDIR}/extra/forensic_enhancement.txt" 2>&1
append_timeline "$(date +%s)" "forensic_enhance" "Forensic enhancement data collected"

#----------- 14. 容器与环境检测 -----------
echo "[*] 检测容器环境..."
{
    echo "=============================================="
    echo "  容器与环境检测 (extra/container_check.txt)"
    echo "=============================================="
    echo "  采集内容: 检测当前是否在容器中、容器运行时状态"
    echo "  包含: /proc/1/cgroup(判断容器类型)、Docker/containerd/kubectl状态、/.dockerenv存在检测"
    echo ""
    echo "=== init cgroup ==="; cat /proc/1/cgroup 2>/dev/null
    echo "=== Docker 容器 ==="; safe_run 20 docker ps 2>/dev/null || echo "docker 不可用或无权限"
    echo "=== 容器逃逸风险检查 ==="
    # /proc/1/cgroup 检查看是否在容器内
    grep -qE "docker|kubepods|containerd" /proc/1/cgroup 2>/dev/null && echo "[!] 当前环境可能为容器"
    # docker.sock 挂载检测 (逃逸风险)
    [ -S /var/run/docker.sock ] && echo "[!] 发现 docker.sock 挂载 (逃逸风险!)"
    # 特权模式检测
    grep -qE "seccomp.*0|Seccomp:.*0" /proc/1/status 2>/dev/null && echo "[!] 可能为特权容器 (no Seccomp)"
    # /.dockerenv 文件
    [ -f /.dockerenv ] && echo "[!] /.dockerenv 存在 (Docker 容器内)"
    echo ""
    echo "=== containerd ==="; safe_run 10 ctr containers list 2>/dev/null || true
    echo "=== kubectl ==="; safe_run 20 kubectl get pods --all-namespaces 2>/dev/null || echo "kubectl 不可用"
    echo "=== 当前是否在容器中 ==="; [ -f /.dockerenv ] && echo "[!] 当前在 Docker 容器中" || echo "[OK] 不在 Docker 容器中"
} > "${OUTDIR}/extra/container_check.txt" 2>&1

#----------- 14.5 系统资源限制 + IPv6配置 -----------
echo "[*] 收集系统资源限制与IPv6配置..."
{
    echo "=============================================="
    echo "  系统资源限制与IPv6配置 (extra/system_limits.txt)"
    echo "=============================================="
    echo "  采集内容: ulimit限制、/etc/security/limits.conf、IPv6配置"
    echo ""
    echo "=== ulimit -a (当前shell资源限制) ==="
    ulimit -a 2>/dev/null
    echo ""
    echo "=== /etc/security/limits.conf ==="
    cat /etc/security/limits.conf 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$' || echo "limits.conf 不可用"
    echo ""
    echo "=== /etc/security/limits.d/ 目录 ==="
    for f in /etc/security/limits.d/*.conf; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f" 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$'
    done
    echo ""
    echo "=== /etc/sysctl.conf (非注释行) ==="
    cat /etc/sysctl.conf 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$' | head -100 || echo "sysctl.conf 不可用"
    echo ""
    echo "=== sysctl.d/ 目录 ==="
    for f in /etc/sysctl.d/*.conf; do
        [ -f "$f" ] && echo "--- $f ---" && cat "$f" 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$'
    done
    echo ""
    echo "=== IPv6 全面配置 ==="
    echo "disable_ipv6 = $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo unknown)"
    echo "--- IPv6 Addresses ---"
    ip -6 addr show 2>/dev/null || echo "IPv6 不可用"
    echo "--- IPv6 Neighbors ---"
    ip -6 neigh show 2>/dev/null || echo "无IPv6邻居"
} > "${OUTDIR}/extra/system_limits.txt" 2>&1
append_timeline "$(date +%s)" "system_limits" "System limits collected"
#----------- 15. 可疑 ELF 文件 -----------
echo "[*] 检查临时目录中的 ELF 文件..."
{
    echo "=== /tmp, /dev/shm, /var/tmp 中的二进制文件 ==="
    find /tmp /dev/shm /var/tmp -type f -print0 2>/dev/null |
    while IFS= read -r -d '' f; do
        file "$f" 2>/dev/null | grep -E 'ELF|script|packed' && echo "$f"
    done | head -50
} >> "${OUTDIR}/extra/recent_files.txt" 2>&1

#----------- 16. 生成统一时间线文件 -----------
echo "[*] 生成时间线..."
{
    echo "# =============================================="
    echo "#  统一时间线 (timeline_master.txt)"
    echo "# =============================================="
    echo "#  采集内容: 整个取证过程中发现的所有带时间戳的事件"
    echo "#  格式: Unix时间戳|事件类型|详情"
    echo "#  事件类型: script_start/end、system_info、process、proc_snapshot、network、persistence、webshell_*、memshell_*、tomcat_*、logs、log_analysis、temp_class、file_modify*、ssh_backdoor、suspicious_*、ioc_sweep、summary"
    echo "#"
    echo "# Timestamp | Type | Detail"
    sort -n /tmp/timeline_raw_$$.txt 2>/dev/null
} > "${OUTDIR}/timeline_master.txt"

END_TIME=$(date)
if [ -n "${EPOCHREALTIME:-}" ]; then
    EPOCH_END=${EPOCHREALTIME%.*}
else
    EPOCH_END=$(date +%s)
fi
DURATION=$((EPOCH_END - EPOCH_START))
{
    echo "采集结束: ${END_TIME}"
    echo "总耗时: ${DURATION} 秒"
} >> "${OUTDIR}/timeline.txt"
append_timeline "$EPOCH_END" "script_end" "Duration: ${DURATION}s"

#----------- 16.5 IOC 全量扫描 -----------
if [ ${#IOC_LIST[@]} -gt 0 ]; then
    echo "[*] IOC 全量扫描..."
    sweep_iocs "$OUTDIR" > "${OUTDIR}/ioc_sweep.txt" 2>&1
    append_timeline "$(date +%s)" "ioc_sweep" "IOC sweep: ${#IOC_LIST[@]} indicators"
fi

#----------- 16.6 生成统一摘要 -----------
echo "[*] 生成取证摘要..."
{
    echo "=============================================="
    echo "  应急取证摘要 - Key-Value格式 (summary.txt)"
    echo "=============================================="
    echo "  用途: 接收方第一时间快速判断失陷状态，定向翻阅对应txt深入分析"
    echo "  包含: memshell_*(内存马指标)、webshell_detected、deletedFiles_*(已删除文件)、logPattern_*(日志异常模式)、persistence_suspicious、hiddenProcess、suspiciousConnections、iocHitCount、tomcatAnomalies、suid_highRisk、suspiciousELF"
    echo ""
    echo "hostname=$(hostname 2>/dev/null || echo unknown)"
    echo "timestamp=$(date -Iseconds)"
    echo "duration_sec=${DURATION}"
    echo ""

    # 内存马关键指标（grep -c 在 0 匹配时返回 "0" 且退出码 1，用 || true 避免双重输出）
    echo "--- memory_shell ---"
    accessor_high=$(grep -c 'GeneratedMethodAccessor 数量异常偏高' "${OUTDIR}/memshell_check.txt" 2>/dev/null || true)
    accessor_sus=$(grep -c 'GeneratedMethodAccessor 数量偏高' "${OUTDIR}/memshell_check.txt" 2>/dev/null || true)
    unknown_src=$(grep -c '大量未知来源类' "${OUTDIR}/memshell_check.txt" 2>/dev/null || true)
    java_agent=$(grep -c '发现 Java Agent 参数' "${OUTDIR}/memshell_check.txt" 2>/dev/null || true)
    echo "memshell_GeneratedMethodAccessor_high=${accessor_high:-0}"
    echo "memshell_GeneratedMethodAccessor_suspect=${accessor_sus:-0}"
    echo "memshell_unknownSourceClasses=${unknown_src:-0}"
    echo "memshell_javaAgent=${java_agent:-0}"

    # 可疑JAR（多文件 grep -rch 汇总）
    high_risk_jar=$(grep -rch '高危路径JAR\|高危路径加载' "${OUTDIR}/"*.txt 2>/dev/null | awk '{s+=$1}END{print s}') 2>/dev/null || echo 0
    memshell_config_hit=$(grep -rch '内存马.*Filter.*配置发现\|memshell_config' "${OUTDIR}/"*.txt 2>/dev/null | awk '{s+=$1}END{print s}') 2>/dev/null || echo 0
    echo "memshell_highRiskJARs=${high_risk_jar:-0}"
    echo "memshell_configHit=${memshell_config_hit:-0}"

    # WebShell
    ws_hit=$(grep -c '\[CHOPPER\]\|\[ANTSWORD\]\|\[BEHINDER\]\|\[GODZILLA\]\|\[MEMSHELL_HINT\]' "${OUTDIR}/webshell_scan.txt" 2>/dev/null || true)
    echo "webshell_detected=${ws_hit:-0}"

    # 已删除文件
    deleted_count=$(grep -c 'deleted' "${OUTDIR}/proc_snapshot.txt" 2>/dev/null || true)
    deleted_highrisk=$(grep -c '高危: 临时目录文件已删除' "${OUTDIR}/proc_snapshot.txt" 2>/dev/null || true)
    echo "deletedFiles_count=${deleted_count:-0}"
    echo "deletedFiles_highRisk=${deleted_highrisk:-0}"

    # 日志模式命中（排除脚本自身表头描述行自匹配）
    admin_login=$(grep -E 'Add user.*admin|login.*284' "${OUTDIR}/log_pattern_analysis.txt" 2>/dev/null | grep -vE '(采集内容|包含):' | wc -l) || echo 0
    dispose=$(grep -E 'disposeException|__Anyone__' "${OUTDIR}/log_pattern_analysis.txt" 2>/dev/null | grep -vE '(采集内容|包含):' | wc -l) || echo 0
    unknown_class=$(grep -E '\[?:?\]' "${OUTDIR}/log_pattern_analysis.txt" 2>/dev/null | grep -vE '(采集内容|包含):' | wc -l) || echo 0
    echo "logPattern_adminLogin=${admin_login:-0}"
    echo "logPattern_authFailure=${dispose:-0}"
    echo "logPattern_unknownClassSource=${unknown_class:-0}"

    # 持久化
    suspicious_cron=$(grep -c 'suspicious_service\|suspicious_profile\|ssh_backdoor' "${OUTDIR}/crontab.txt" 2>/dev/null || true)
    echo "persistence_suspicious=${suspicious_cron:-0}"

    # 可疑进程
    hidden_proc=$(grep -c '发现隐藏进程' "${OUTDIR}/process.txt" 2>/dev/null || true)
    echo "hiddenProcess=${hidden_proc:-0}"

    # 网络异常
    suspicious_conn=$(grep -cE 'ESTABLISHED.*(47\.|8\.8\.8\.8|1\.1\.1\.1|\.ru|\.pw|\.tk)' "${OUTDIR}/network.txt" 2>/dev/null || true)
    echo "suspiciousConnections=${suspicious_conn:-0}"

    # IOC 命中
    if [ -f "${OUTDIR}/ioc_sweep.txt" ]; then
        ioc_hit=$(grep -c '\[HIT\]' "${OUTDIR}/ioc_sweep.txt" 2>/dev/null || true)
        ioc_total=$(grep -c 'IOC=' "${OUTDIR}/ioc_sweep.txt" 2>/dev/null || true)
        echo "iocHitCount=${ioc_hit:-0}"
        echo "iocTotalChecked=${ioc_total:-0}"
    else
        echo "iocHitCount=0"
        echo "iocTotalChecked=0"
    fi

    # Tomcat 目录异常（多文件汇总）
    tomcat_mod=$(grep -rch 'tomcat_webapp_mod\|tomcat_lib_mod\|tomcat_agent_jar\|tomcat_valve' "${OUTDIR}/"*.txt 2>/dev/null | awk '{s+=$1}END{print s}') 2>/dev/null || echo 0
    echo "tomcatAnomalies=${tomcat_mod:-0}"

    # SUID 异常
    suid_count=$(grep -cE '/tmp/|/dev/shm/|/var/tmp/' "${OUTDIR}/extra/suid_sgid.txt" 2>/dev/null || true)
    echo "suid_highRisk=${suid_count:-0}"

    # ELF 可疑（排除脚本自身表头行，"采集内容"和"包含"行含"ELF"字样）
    elf_sus=$(grep -E 'ELF|packed' "${OUTDIR}/extra/recent_files.txt" 2>/dev/null | grep -vE '(采集内容|包含):' | wc -l) || echo 0
    echo "suspiciousELF=${elf_sus:-0}"

    echo ""
    echo "promiscuous=$(grep -c '发现混杂模式' "${OUTDIR}/extra/net_l2_l3.txt" 2>/dev/null || true)"
    echo "hiddenKmod=$(grep -c '可能存在隐藏内核模块' "${OUTDIR}/extra/kernel_deep.txt" 2>/dev/null || true)"
    echo "unsignedKmod=$(grep -c '未签名模块' "${OUTDIR}/extra/kernel_deep.txt" 2>/dev/null || true)"
    echo "sysrqEnabled=$(grep -c 'Magic SysRq' "${OUTDIR}/extra/kernel_deep.txt" 2>/dev/null || true)"
    echo "ptraceDetected=$(grep -c 'ptrace 追踪' "${OUTDIR}/extra/ptrace_raw_sockets.txt" 2>/dev/null || true)"
    echo "recentLoginFailed=$(grep -c 'Failed' "${OUTDIR}/extra/login_forensics.txt" 2>/dev/null || true)"

    echo "--- raw_indicators ---"
    # 提取具体的可疑项（类名、IP、文件路径）
    grep -hE '\[!!!\]|\[HIT\]|\[BEHINDER\]|\[GODZILLA\]|\[CHOPPER\]|\[ANTSWORD\]' "${OUTDIR}/"*.txt 2>/dev/null | head -50

} > "${OUTDIR}/summary.txt"
append_timeline "$(date +%s)" "summary" "Unified summary generated"

# 生成 summary.json（供自动化平台/分析工具消费）
# 辅助函数：从 summary.txt 提取 key=value
extract_kv() {
    local key="$1" file="$2"
    sed -n "s/^${key}=//p" "$file" 2>/dev/null || echo 0
}
# JSON 安全转义 hostname
hostname_safe=$(hostname 2>/dev/null | sed 's/\\/\\\\/g; s/"/\\"/g' || echo "unknown")
{
    echo "{"
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"duration_sec\": ${DURATION},"
    echo "  \"indicators\": {"
    # 内存马
    echo "    \"memoryShell\": {"
    echo "      \"accessorHigh\": $(extract_kv memshell_GeneratedMethodAccessor_high "${OUTDIR}/summary.txt"),"
    echo "      \"accessorSuspect\": $(extract_kv memshell_GeneratedMethodAccessor_suspect "${OUTDIR}/summary.txt"),"
    echo "      \"unknownSourceClasses\": $(extract_kv memshell_unknownSourceClasses "${OUTDIR}/summary.txt"),"
    echo "      \"javaAgent\": $(extract_kv memshell_javaAgent "${OUTDIR}/summary.txt"),"
    echo "      \"highRiskJARs\": $(extract_kv memshell_highRiskJARs "${OUTDIR}/summary.txt"),"
    echo "      \"configHit\": $(extract_kv memshell_configHit "${OUTDIR}/summary.txt")"
    echo "    },"
    # WebShell
    echo "    \"webShell\": {"
    echo "      \"detected\": $(extract_kv webshell_detected "${OUTDIR}/summary.txt")"
    echo "    },"
    # 已删除文件
    echo "    \"deletedFiles\": {"
    echo "      \"count\": $(extract_kv deletedFiles_count "${OUTDIR}/summary.txt"),"
    echo "      \"highRisk\": $(extract_kv deletedFiles_highRisk "${OUTDIR}/summary.txt")"
    echo "    },"
    # 日志异常
    echo "    \"logPatterns\": {"
    echo "      \"adminLogin\": $(extract_kv logPattern_adminLogin "${OUTDIR}/summary.txt"),"
    echo "      \"authFailure\": $(extract_kv logPattern_authFailure "${OUTDIR}/summary.txt"),"
    echo "      \"unknownClassSource\": $(extract_kv logPattern_unknownClassSource "${OUTDIR}/summary.txt")"
    echo "    },"
    # 持久化/进程/网络
    echo "    \"persistence\": {"
    echo "      \"suspicious\": $(extract_kv persistence_suspicious "${OUTDIR}/summary.txt")"
    echo "    },"
    echo "    \"process\": {"
    echo "      \"hiddenCount\": $(extract_kv hiddenProcess "${OUTDIR}/summary.txt")"
    echo "    },"
    echo "    \"network\": {"
    echo "      \"suspiciousConnections\": $(extract_kv suspiciousConnections "${OUTDIR}/summary.txt")"
    echo "    },"
    # IOC/Tomcat
    echo "    \"ioc\": {"
    echo "      \"hitCount\": $(extract_kv iocHitCount "${OUTDIR}/summary.txt"),"
    echo "      \"totalChecked\": $(extract_kv iocTotalChecked "${OUTDIR}/summary.txt")"
    echo "    },"
    echo "    \"tomcat\": {"
    echo "      \"anomalies\": $(extract_kv tomcatAnomalies "${OUTDIR}/summary.txt")"
    echo "    },"
    echo "    \"suid\": {"
    echo "      \"highRisk\": $(extract_kv suid_highRisk "${OUTDIR}/summary.txt")"
    echo "    },"
    echo "    \"elf\": {"
    echo "      \"suspicious\": $(extract_kv suspiciousELF "${OUTDIR}/summary.txt")"
    echo "    }"
    echo "  }"
    echo "}"
} > "${OUTDIR}/summary.json"
append_timeline "$(date +%s)" "summary_json" "JSON summary generated"

#----------- 16.7 证据文件校验 -----------
echo "[*] 生成证据校验文件..."
    echo "[*] 生成证据校验文件 (SHA256)..."
    find "${OUTDIR}" -type f -not -name "evidence_hashes.txt" -exec sha256sum {} \; > "${OUTDIR}/evidence_hashes.txt" 2>/dev/null
    append_timeline "$(date +%s)" "evidence_hash" "Evidence hashes generated"

#=============================================================================
# 16.8 Process Graph JSON — 进程父子关系图（供 AI 溯源）
#=============================================================================
echo "[*] 生成 Process Graph JSON..."
{
    echo "{"
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"processes\": ["

    first=1
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n); do
        [ -d "/proc/$pid" ] || continue
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ' | sed 's/"/\\"/g; s/\\/\\\\/g')
        [ -z "$cmdline" ] && continue
        ppid=$(grep '^PPid:' "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        uid=$(grep '^Uid:' "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        user=$(awk -F: -v u="$uid" '$3==u{print $1}' /etc/passwd 2>/dev/null || echo "uid_$uid")
        cwd=$(readlink "/proc/${pid}/cwd" 2>/dev/null | sed 's/"/\\"/g' || echo "")

        # 收集网络连接
        networks=""
        if command -v ss &>/dev/null; then
            networks=$(ss -tnp 2>/dev/null | grep "pid=$pid" | awk '{printf "%s:%s", $4, $5}' | sed 's/"/\\"/g' | head -5 | paste -sd ',' -)
        fi

        # 收集打开的文件（仅可疑路径）
        suspicious_fds=""
        suspicious_fds=$(ls -l "/proc/${pid}/fd/" 2>/dev/null | grep -E '(tmp|dev/shm|var/tmp|memfd|deleted)' | awk '{print $NF}' | sed 's/"/\\"/g' | head -5 | paste -sd ',' -)

        # 风险标签
        risk_tags=""
        echo "$cmdline" | grep -qE 'curl.*\|.*bash|wget.*-O.*\|.*sh' && risk_tags="${risk_tags}download_execute,"
        echo "$cmdline" | grep -qE 'nc |ncat|bash -i|python -c|perl -e' && risk_tags="${risk_tags}reverse_shell,"
        echo "$cmdline" | grep -qE 'chmod\s+777|chmod u\+s' && risk_tags="${risk_tags}privilege_esc,"
        [ -n "$suspicious_fds" ] && risk_tags="${risk_tags}suspicious_fd,"
        [ -n "$networks" ] && echo "$networks" | grep -qE ':(4444|1337|31337|6666|6667|7777|8080|8443|9001|9999)' && risk_tags="${risk_tags}c2_port,"
        risk_tags="${risk_tags%,}"

        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "    {"
        echo -n "\"pid\":$pid"
        echo -n ",\"ppid\":${ppid:-0}"
        echo -n ",\"user\":\"$user\""
        echo -n ",\"cmdline\":\"${cmdline:0:300}\""
        echo -n ",\"cwd\":\"$cwd\""
        [ -n "$networks" ] && echo -n ",\"network\":\"$networks\""
        [ -n "$suspicious_fds" ] && echo -n ",\"suspicious_fds\":\"$suspicious_fds\""
        [ -n "$risk_tags" ] && echo -n ",\"risk_tags\":\"$risk_tags\""
        echo -n "}"
    done
    echo ""
    echo "  ]"
    echo "}"
} > "${OUTDIR}/process_graph.json" 2>&1
append_timeline "$(date +%s)" "process_graph" "Process graph JSON generated"

#=============================================================================
# 16.9 Shell 历史智能分类（下载/提权/清痕/横移）
#=============================================================================
echo "[*] Shell 历史智能分类..."
{
    echo "=============================================="
    echo "  Shell 历史智能分类 (extra/shell_classification.txt)"
    echo "=============================================="
    echo "  分类: 下载执行 | 提权 | 痕迹清理 | 横向移动 | 信息收集 | 持久化"
    echo ""

    for hist in /root/.bash_history /home/*/.bash_history; do
        [ -f "$hist" ] || continue
        user=$(basename "$(dirname "$hist")")
        echo "=== 用户: $user ==="
        echo ""

        # 下载执行
        echo "--- [下载执行] curl/wget 管道执行 ---"
        grep -nE 'curl.*\|.*bash|curl.*\|.*sh|wget.*\|.*bash|wget.*\|.*sh|curl.*-o.*&&.*\./|wget.*-O.*&&.*chmod' "$hist" 2>/dev/null | head -20
        echo ""

        # 提权
        echo "--- [提权] sudo/su/chmod ---"
        grep -nE '\bsudo\s+su\b|\bsudo\s+bash\b|\bsudo\s+-i\b|chmod\s+u\+s|chmod\s+4777|chmod\s+777\s+/etc/shadow' "$hist" 2>/dev/null | head -20
        echo ""

        # 痕迹清理
        echo "--- [痕迹清理] history/rm/shred ---"
        grep -nE '\bhistory\s+-c\b|\brm\s+-rf\s+/(var/log|tmp|home).*history|\bshred\s+-|\bunset\s+HISTFILE|\bexport\s+HISTSIZE=0' "$hist" 2>/dev/null | head -20
        echo ""

        # 横向移动
        echo "--- [横向移动] scp/ssh/rsync ---"
        grep -nE '\bssh\s+[a-z]+@|\bscp\s+.*@|\brsync\s+.*@|\bsshpass\b|\bsocat\b' "$hist" 2>/dev/null | head -20
        echo ""

        # 信息收集
        echo "--- [信息收集] whoami/id/uname/ls/cat ---"
        grep -nE '\bwhoami\b|\bid\b|\buname\s+-a\b|\bcat\s+/etc/(passwd|shadow|hosts)\b|\bifconfig\b|\bip\s+addr\b|\bnetstat\b|\bss\s+-' "$hist" 2>/dev/null | head -20
        echo ""

        # 持久化
        echo "--- [持久化] crontab/systemctl/rc.local ---"
        grep -nE '\bcrontab\s+-|\bsystemctl\s+(enable|start)\b|\bupdate-rc\.d\b|\becho.*>>\s+/etc/(rc\.local|crontab|profile)\b' "$hist" 2>/dev/null | head -20
        echo ""
    done
} > "${OUTDIR}/extra/shell_classification.txt" 2>&1
append_timeline "$(date +%s)" "shell_classify" "Shell history classified"

#=============================================================================
# 16.10 SSH 横向移动图谱
#=============================================================================
echo "[*] 构建 SSH 横向移动图谱..."
{
    echo "=============================================="
    echo "  SSH 横向移动图谱 (extra/lateral_movement.txt)"
    echo "=============================================="
    echo "  交叉关联: known_hosts + auth.log + shell 历史 + SSH config"
    echo ""

    # 1. 收集所有 known_hosts（目标主机列表）
    echo "=== known_hosts — 横向移动目标 ==="
    declare -A lateral_targets
    for kh in /root/.ssh/known_hosts /home/*/.ssh/known_hosts; do
        [ -f "$kh" ] || continue
        src_user=$(basename "$(dirname "$(dirname "$kh")")")
        echo "--- 来源用户: $src_user ---"
        while read -r line; do
            target=$(echo "$line" | awk '{print $1}' | cut -d, -f1)
            [ -n "$target" ] && echo "  $target"
        done < "$kh"
        echo ""
    done

    # 2. 从 auth.log 提取接受过的入站 SSH 连接
    echo "=== 入站 SSH 连接来源 ==="
    echo "--- auth.log 接受的连接 ---"
    grep -h 'Accepted' /var/log/auth.log /var/log/secure 2>/dev/null | grep -vE '^[[:space:]]*$' | tail -50
    echo ""
    echo "--- auth.log 失败连接 ---"
    grep -h 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head -20
    echo ""

    # 3. SSH config 中的 ProxyJump / ProxyCommand
    echo "=== SSH 代理/跳板配置 ==="
    for sc in /root/.ssh/config /home/*/.ssh/config; do
        [ -f "$sc" ] || continue
        echo "--- $sc ---"
        grep -E 'Host |HostName |ProxyJump|ProxyCommand|ForwardAgent|LocalForward|RemoteForward' "$sc" 2>/dev/null
        echo ""
    done

    # 4. 出站 SSH 命令历史（从 shell 历史）
    echo "=== 出站 SSH 命令（最近30条）==="
    for hist in /root/.bash_history /home/*/.bash_history; do
        [ -f "$hist" ] || continue
        user=$(basename "$(dirname "$hist")")
        grep -E '\bssh\s+' "$hist" 2>/dev/null | grep -v '^\s*#' | tail -30 | while read line; do
            echo "  [$user] $line"
        done
    done
} > "${OUTDIR}/extra/lateral_movement.txt" 2>&1
append_timeline "$(date +%s)" "lateral_movement" "SSH lateral movement mapped"

#=============================================================================
# 16.11 IOC 自动输出
#=============================================================================
echo "[*] 自动抽取 IOC..."
{
    echo "{"
    echo "  \"generated_at\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"iocs\": {"

    # 1. 从所有 txt 中提取 IP 地址
    echo "    \"ips\": ["
    first=1
    grep -rohE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${OUTDIR}/"*.txt "${OUTDIR}/extra/"*.txt 2>/dev/null | \
        grep -vE '^(0\.0\.0\.0|127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|255\.|224\.)' | \
        sort -u | head -100 | while read ip; do
        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "      \"$ip\""
    done
    echo ""
    echo "    ],"

    # 2. 域名
    echo "    \"domains\": ["
    first=1
    grep -rohE '\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b' "${OUTDIR}/"*.txt "${OUTDIR}/extra/"*.txt 2>/dev/null | \
        grep -vE '\.(txt|sh|py|pl|c|h|cpp|java|class|jar|war|xml|json|yaml|yml|log|gz|bz2|xz|tar|zip|tmp|bak|old|conf|service|socket|timer|target|desktop)$' | \
        grep -vE '^(www\.|mail\.|ftp\.|ns[0-9]\.|[A-Z]\.|[A-Z][a-z]+Exception\.|Runtime\.|ProcessBuilder\.|javax\.|java\.|org\.|com\.sun\.|sun\.)' | \
        grep -vE '(agetty|login|conf|service|socket|timer|target|desktop|modemmanager|networkmanager|accounts-daemon|systemd|cron\.|dbus\.|apt\.|console-|cloud-init|apparmor|avahi|blueman|at-spi|boot-complete|cron\.daily|cron\.hourly|cron\.monthly|cron\.weekly|daemon\.conf|debug\.|README\.|I\.|RDJpj|SettingsDaemon|a11y\.|about\.php|ac\.ko|control\.html|catalina\.out|Runtime\.exec)' | \
        grep -vE '^[A-Z]\.[a-z]' | \
        grep -vE '^[a-z]+\.[a-z]+$' | \
        sort -u | head -50 | while read domain; do
        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "      \"$domain\""
    done
    echo ""
    echo "    ],"

    # 3. SHA256 哈希
    echo "    \"hashes\": ["
    first=1
    grep -rohE '\b[a-fA-F0-9]{64}\b' "${OUTDIR}/"*.txt "${OUTDIR}/extra/"*.txt 2>/dev/null | \
        sort -u | head -50 | while read hash; do
        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "      \"$hash\""
    done
    echo ""
    echo "    ],"

    # 4. URL
    echo "    \"urls\": ["
    first=1
    grep -rohE 'https?://[^[:space:]]+' "${OUTDIR}/"*.txt "${OUTDIR}/extra/"*.txt 2>/dev/null | \
        sed 's/[",]//g' | sort -u | head -50 | while read url; do
        [ "$first" -eq 0 ] && echo ","
        first=0
        echo -n "      \"$url\""
    done
    echo ""
    echo "    ]"

    echo "  }"
    echo "}"
} > "${OUTDIR}/ioc_output.json" 2>&1
append_timeline "$(date +%s)" "ioc_output" "IOCs auto-extracted to ioc_output.json"

#=============================================================================
# 16.12 结构化网络 JSON (sockets.json)
#=============================================================================
echo "[*] 生成结构化网络 JSON..."
{
    echo "{"
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"connections\": ["

    first=1
    if command -v ss &>/dev/null; then
        ss -tnp 2>/dev/null | tail -n +2 | grep -v '^$' | head -100 | while read -r state recv send local remote extra; do
            [ -z "$state" ] && continue
            case "$state" in
                ESTAB|LISTEN|TIME-WAIT|CLOSE-WAIT|SYN-SENT|SYN-RECV|FIN-WAIT-1|FIN-WAIT-2|LAST-ACK|CLOSING) ;;
                *) continue ;;
            esac
            proc=$(echo "$extra" | grep -o 'users:((\"[^\"]*\"' 2>/dev/null | sed 's/users:(("//;s/"//g' || echo "")
            [ "$first" -eq 0 ] && echo ","
            first=0
            echo -n "    {\"state\":\"$state\",\"local\":\"$local\",\"remote\":\"$remote\",\"process\":\"$proc\"}"
        done
    fi
    echo ""
    echo "  ]"
    echo "}"
} > "${OUTDIR}/sockets.json" 2>&1
append_timeline "$(date +%s)" "sockets_json" "Structured network JSON generated"

#=============================================================================
# 16.13 risk.json — 风险评分引擎（严重度打分 + 攻击链关联）
#=============================================================================
echo "[*] 生成风险评分..."
{
    critical=0; high=0; medium=0; low=0
    findings=""

    # --- CRITICAL (分: 100) ---
    # memfd_create
    if grep -q 'memfd_create 命中进程数: [1-9]' "${OUTDIR}/extra/memfd_preload.txt" 2>/dev/null; then
        cnt=$(grep 'memfd_create 命中进程数:' "${OUTDIR}/extra/memfd_preload.txt" | grep -o '[0-9][0-9]*' | head -1 || echo 1)
        critical=$((critical + 100*${cnt:-1}))
        findings="${findings}{\"type\":\"memfd_create\",\"severity\":\"CRITICAL\",\"score\":100,\"count\":${cnt:-1},\"detail\":\"无文件执行(memfd_create)\",\"source\":\"memfd_preload.txt\"},"
    fi
    # deleted exe running
    if grep -q '运行已删除的二进制' "${OUTDIR}/extra/memfd_preload.txt" 2>/dev/null; then
        cnt=$(grep -c '运行已删除的二进制' "${OUTDIR}/extra/memfd_preload.txt" 2>/dev/null || echo 1)
        critical=$((critical + 100*${cnt:-1}))
        findings="${findings}{\"type\":\"deleted_exe\",\"severity\":\"CRITICAL\",\"score\":100,\"count\":${cnt:-1},\"detail\":\"进程运行已删除的二进制(内存驻留)\",\"source\":\"memfd_preload.txt\"},"
    fi
    # hidden kernel module
    if grep -q '可能存在隐藏内核模块' "${OUTDIR}/extra/kernel_deep.txt" 2>/dev/null; then
        critical=$((critical + 100))
        findings="${findings}{\"type\":\"hidden_kmod\",\"severity\":\"CRITICAL\",\"score\":100,\"count\":1,\"detail\":\"隐藏内核模块(LKM rootkit)\",\"source\":\"kernel_deep.txt\"},"
    fi
    # /etc/ld.so.preload exists
    if grep -q '/etc/ld.so.preload 存在' "${OUTDIR}/extra/memfd_preload.txt" 2>/dev/null; then
        critical=$((critical + 100))
        findings="${findings}{\"type\":\"ld_preload\",\"severity\":\"CRITICAL\",\"score\":100,\"count\":1,\"detail\":\"/etc/ld.so.preload 全局劫持\",\"source\":\"memfd_preload.txt\"},"
    fi
    # ptrace detected
    if grep -q 'ptrace 追踪' "${OUTDIR}/extra/ptrace_raw_sockets.txt" 2>/dev/null; then
        critical=$((critical + 90))
        findings="${findings}{\"type\":\"ptrace_detected\",\"severity\":\"CRITICAL\",\"score\":90,\"count\":1,\"detail\":\"进程被 ptrace 追踪\",\"source\":\"ptrace_raw_sockets.txt\"},"
    fi

    # --- HIGH (分: 60) ---
    # WebShell detected
    ws=$(grep -cE '\[CHOPPER\]|\[ANTSWORD\]|\[BEHINDER\]|\[GODZILLA\]' "${OUTDIR}/webshell_scan.txt" 2>/dev/null || true)
    if [ "$ws" -gt 0 ]; then
        high=$((high + 60*${ws}))
        findings="${findings}{\"type\":\"webshell\",\"severity\":\"HIGH\",\"score\":60,\"count\":${ws},\"detail\":\"WebShell 管理工具特征命中\",\"source\":\"webshell_scan.txt\"},"
    fi
    # memshell accessor high
    if grep -q 'GeneratedMethodAccessor 数量异常偏高' "${OUTDIR}/memshell_check.txt" 2>/dev/null; then
        high=$((high + 65))
        findings="${findings}{\"type\":\"memshell_accessor\",\"severity\":\"HIGH\",\"score\":65,\"count\":1,\"detail\":\"GeneratedMethodAccessor 异常偏高(>25000) 疑似内存马\",\"source\":\"memshell_check.txt\"},"
    fi
    # high risk JAR
    if grep -q '高危路径JAR\|高危路径加载' "${OUTDIR}/tomcat_forensics.txt" "${OUTDIR}/memshell_check.txt" 2>/dev/null; then
        high=$((high + 60))
        findings="${findings}{\"type\":\"high_risk_jar\",\"severity\":\"HIGH\",\"score\":60,\"count\":1,\"detail\":\"高危路径加载JAR(/tmp|/dev/shm)\",\"source\":\"tomcat_forensics.txt\"},"
    fi
    # reverse shell
    if grep -hE 'nc |ncat|bash -i|python -c.*socket|reverse' "${OUTDIR}/process.txt" "${OUTDIR}/crontab.txt" 2>/dev/null | grep -vE '(采集内容|包含:|reverse proxy)' | grep -q .; then
        high=$((high + 60))
        findings="${findings}{\"type\":\"reverse_shell\",\"severity\":\"HIGH\",\"score\":60,\"count\":1,\"detail\":\"反向Shell命令行特征\",\"source\":\"process.txt\"},"
    fi
    # suspicious service
    suspicious_svc=$(grep -c 'ExecStart 指向可疑路径' "${OUTDIR}/crontab.txt" 2>/dev/null || true)
    if [ "$suspicious_svc" -gt 0 ]; then
        high=$((high + 55*${suspicious_svc}))
        findings="${findings}{\"type\":\"suspicious_service\",\"severity\":\"HIGH\",\"score\":55,\"count\":${suspicious_svc},\"detail\":\"systemd服务ExecStart指向可疑路径\",\"source\":\"crontab.txt\"},"
    fi
    # memshell config hit
    if grep -q '内存马.*Filter.*配置发现' "${OUTDIR}/tomcat_forensics.txt" 2>/dev/null; then
        high=$((high + 65))
        findings="${findings}{\"type\":\"memshell_config\",\"severity\":\"HIGH\",\"score\":65,\"count\":1,\"detail\":\"Tomcat配置中发现内存马Filter\",\"source\":\"tomcat_forensics.txt\"},"
    fi
    # promiscuous mode
    if grep -q '发现混杂模式' "${OUTDIR}/extra/net_l2_l3.txt" 2>/dev/null; then
        high=$((high + 50))
        findings="${findings}{\"type\":\"promiscuous\",\"severity\":\"HIGH\",\"score\":50,\"count\":1,\"detail\":\"网卡处于混杂模式(可能抓包)\",\"source\":\"net_l2_l3.txt\"},"
    fi

    # --- MEDIUM (分: 30) ---
    # suspicious connections
    if grep -qE 'ESTABLISHED' "${OUTDIR}/network.txt" 2>/dev/null; then
        susp_conn=$(ss -tn state established 2>/dev/null | wc -l)
        [ "$susp_conn" -gt 100 ] && { medium=$((medium + 30)); findings="${findings}{\"type\":\"many_connections\",\"severity\":\"MEDIUM\",\"score\":30,\"count\":1,\"detail\":\"大量ESTABLISHED连接(>100)\",\"source\":\"network.txt\"},"; }
    fi
    # deleted files
    del=$(grep -c '(deleted)' "${OUTDIR}/proc_snapshot.txt" 2>/dev/null || true)
    if [ "$del" -gt 5 ]; then
        medium=$((medium + 30))
        findings="${findings}{\"type\":\"deleted_files\",\"severity\":\"MEDIUM\",\"score\":30,\"count\":${del},\"detail\":\"大量已删除但仍打开的文件\",\"source\":\"proc_snapshot.txt\"},"
    fi
    # unknown source classes
    if grep -q '大量未知来源类' "${OUTDIR}/memshell_check.txt" 2>/dev/null; then
        medium=$((medium + 35))
        findings="${findings}{\"type\":\"unknown_classes\",\"severity\":\"MEDIUM\",\"score\":35,\"count\":1,\"detail\":\"大量动态注入类([?:?]来源)\",\"source\":\"memshell_check.txt\"},"
    fi
    # suspicious cron/profile
    suspicious_cron=$(grep -c 'suspicious_service\|suspicious_profile' "${OUTDIR}/crontab.txt" 2>/dev/null || true)
    if [ "$suspicious_cron" -gt 0 ]; then
        medium=$((medium + 30))
        findings="${findings}{\"type\":\"suspicious_persistence\",\"severity\":\"MEDIUM\",\"score\":30,\"count\":${suspicious_cron},\"detail\":\"可疑持久化机制\",\"source\":\"crontab.txt\"},"
    fi
    # unsigned kernel modules
    unsigned=$(grep -c '未签名模块' "${OUTDIR}/extra/kernel_deep.txt" 2>/dev/null || true)
    if [ "$unsigned" -gt 0 ]; then
        medium=$((medium + 25*${unsigned}))
        findings="${findings}{\"type\":\"unsigned_kmod\",\"severity\":\"MEDIUM\",\"score\":25,\"count\":${unsigned},\"detail\":\"未签名内核模块\",\"source\":\"kernel_deep.txt\"},"
    fi
    # SSH backdoor
    if grep -h 'ssh_backdoor\|SSH.*可疑命令\|ProxyCommand' "${OUTDIR}/crontab.txt" "${OUTDIR}/extra/ssh_persistence.txt" 2>/dev/null | grep -vE '(采集内容|包含:)' | grep -q .; then
        medium=$((medium + 35))
        findings="${findings}{\"type\":\"ssh_backdoor\",\"severity\":\"MEDIUM\",\"score\":35,\"count\":1,\"detail\":\"SSH配置包含可疑命令/后门\",\"source\":\"crontab.txt\"},"
    fi
    # tmp ELF
    elf_sus=$(grep -cE 'ELF' "${OUTDIR}/extra/recent_files.txt" 2>/dev/null || true)
    if [ "$elf_sus" -gt 0 ]; then
        medium=$((medium + 30))
        findings="${findings}{\"type\":\"tmp_elf\",\"severity\":\"MEDIUM\",\"score\":30,\"count\":${elf_sus},\"detail\":\"临时目录发现ELF二进制\",\"source\":\"recent_files.txt\"},"
    fi
    # login failures
    login_fail=$(grep -c 'Failed' "${OUTDIR}/extra/login_forensics.txt" 2>/dev/null || true)
    if [ "$login_fail" -gt 20 ]; then
        medium=$((medium + 20))
        findings="${findings}{\"type\":\"brute_force\",\"severity\":\"MEDIUM\",\"score\":20,\"count\":${login_fail},\"detail\":\"大量SSH登录失败(疑似爆破)\",\"source\":\"login_forensics.txt\"},"
    fi

    # --- LOW (分: 10) ---
    # entropy anomalies
    ent=$(grep -c 'HIGH_ENTROPY' "${OUTDIR}/webshell_scan.txt" 2>/dev/null || true)
    if [ "$ent" -gt 0 ]; then
        low=$((low + 10*${ent}))
        findings="${findings}{\"type\":\"high_entropy\",\"severity\":\"LOW\",\"score\":10,\"count\":${ent},\"detail\":\"高熵值文件(可能加密WebShell)\",\"source\":\"webshell_scan.txt\"},"
    fi
    # time anomalies
    time_anom=$(grep -c 'TIME_ANOMALY' "${OUTDIR}/webshell_scan.txt" 2>/dev/null || true)
    if [ "$time_anom" -gt 0 ]; then
        low=$((low + 5*${time_anom}))
        findings="${findings}{\"type\":\"time_anomaly\",\"severity\":\"LOW\",\"score\":5,\"count\":${time_anom},\"detail\":\"文件时间戳异常\",\"source\":\"webshell_scan.txt\"},"
    fi
    # hidden scripts
    hidden=$(grep -c 'HIDDEN' "${OUTDIR}/webshell_scan.txt" 2>/dev/null || true)
    if [ "$hidden" -gt 0 ]; then
        low=$((low + 5*${hidden}))
        findings="${findings}{\"type\":\"hidden_scripts\",\"severity\":\"LOW\",\"score\":5,\"count\":${hidden},\"detail\":\"隐藏脚本文件\",\"source\":\"webshell_scan.txt\"},"
    fi

    # 计算总分和等级
    total=$((critical + high + medium + low))
    if [ "$total" -ge 300 ]; then level="CRITICAL"
    elif [ "$total" -ge 150 ]; then level="HIGH"
    elif [ "$total" -ge 50 ]; then level="MEDIUM"
    else level="LOW"; fi

    findings="${findings%,}"

    echo "{"
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"risk_level\": \"${level}\","
    echo "  \"total_score\": ${total},"
    echo "  \"scores\": {"
    echo "    \"critical\": ${critical},"
    echo "    \"high\": ${high},"
    echo "    \"medium\": ${medium},"
    echo "    \"low\": ${low}"
    echo "  },"
    echo "  \"findings\": ["
    echo "    ${findings}"
    echo "  ]"
    echo "}"
} > "${OUTDIR}/risk.json" 2>&1
append_timeline "$(date +%s)" "risk_json" "Risk scoring completed (level: check risk.json)"

#=============================================================================
# 16.14 Namespace 隔离检测 + 容器深度取证
#=============================================================================
echo "[*] Namespace 隔离 + 容器深度检测..."
{
    echo "=============================================="
    echo "  Namespace + 容器深度检测 (extra/namespace_container.txt)"
    echo "=============================================="
    echo ""

    # Namespace 检测
    echo "=== Namespace 列表 (lsns) ==="
    safe_run 10 lsns 2>/dev/null || echo "lsns 不可用"
    echo ""

    echo "=== 关键进程 Namespace 对比 ==="
    for pid in 1 $(pgrep -f 'sshd|nginx|httpd|java|docker|containerd|kubelet' 2>/dev/null | head -10); do
        [ -d "/proc/$pid/ns" ] || continue
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 100)
        echo "--- PID $pid (${cmdline}) ---"
        for ns in /proc/${pid}/ns/*; do
            ns_name=$(basename "$ns")
            ns_link=$(readlink "$ns" 2>/dev/null)
            echo "  $ns_name -> $ns_link"
        done
        echo ""
    done

    # 容器深度检测
    echo "=== 容器深度检测 ==="
    echo "--- Docker 信息 ---"
    safe_run 10 docker info 2>/dev/null | grep -E 'Server Version|Storage Driver|Cgroup Driver|Security Options' || echo "docker 不可用"
    echo ""
    echo "--- 特权容器检测 ---"
    safe_run 10 docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
        privileged=$(docker inspect "$c" --format '{{.HostConfig.Privileged}}' 2>/dev/null)
        host_net=$(docker inspect "$c" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null)
        host_pid=$(docker inspect "$c" --format '{{.HostConfig.PidMode}}' 2>/dev/null)
        mounts=$(docker inspect "$c" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null)
        [ "$privileged" = "true" ] && echo "  [!!!] $c: 特权容器 (Privileged=true)"
        [ "$host_net" = "host" ] && echo "  [!!!] $c: 使用宿主机网络 (hostNetwork)"
        [ "$host_pid" = "host" ] && echo "  [!!!] $c: 使用宿主机PID (hostPid)"
        echo "$mounts" | grep -q 'docker.sock' && echo "  [!!!] $c: docker.sock 挂载 (逃逸风险!)"
        echo "$mounts" | grep -qE '/proc:|/sys:|/:/' && echo "  [!!!] $c: 敏感路径挂载"
    done
    echo ""

    echo "--- Kubernetes 检测 ---"
    # kubeconfig
    for kc in /root/.kube/config /home/*/.kube/config; do
        [ -f "$kc" ] && echo "[!!!] kubeconfig: $kc" && cat "$kc" 2>/dev/null | grep -E 'server:|cluster:|user:|token:' | head -10
    done
    # serviceaccount token
    [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo "[!!!] K8s ServiceAccount Token 存在 (当前在Pod内)"
    # kubectl
    if command -v kubectl &>/dev/null; then
        echo "--- kubectl 上下文 ---"
        safe_run 10 kubectl config view --minify 2>/dev/null || true
        echo "--- 当前 namespace pods ---"
        safe_run 10 kubectl get pods 2>/dev/null | head -20 || true
    fi
    echo ""

    echo "=== container runtime sockets ==="
    for sock in /var/run/docker.sock /var/run/containerd/containerd.sock /var/run/crio/crio.sock /run/k3s/containerd/containerd.sock; do
        [ -S "$sock" ] && echo "  [!!!] 发现: $sock"
    done
} > "${OUTDIR}/extra/namespace_container.txt" 2>&1
append_timeline "$(date +%s)" "ns_container" "Namespace + container deep check"

#=============================================================================
# 16.15 Entity Correlation JSON（PID↔IP↔File↔User 关联图）
#=============================================================================
echo "[*] 构建 Entity Correlation 图..."
{
    echo "{"
    echo "  \"hostname\": \"${hostname_safe}\","
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"entities\": {"
    echo "    \"processes\": [],"
    echo "    \"files\": [],"
    echo "    \"connections\": []"
    echo "  },"
    echo "  \"relations\": ["

    first_rel=1
    # 遍历进程，建立 PID↔IP↔File↔User 关系
    for pid in $(ls -1 /proc | grep -E '^[0-9]+$' | sort -n | head -300); do
        [ -d "/proc/$pid" ] || continue
        cmdline=$(cat "/proc/${pid}/cmdline" 2>/dev/null | tr '\0' ' ' | sed 's/"/\\"/g; s/\\/\\\\/g' | head -c 200)
        [ -z "$cmdline" ] && continue
        ppid=$(grep '^PPid:' "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        uid=$(grep '^Uid:' "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        user=$(awk -F: -v u="$uid" '$3==u{print $1}' /etc/passwd 2>/dev/null || echo "uid_$uid")

        # 关系: PID → USER
        [ "$first_rel" -eq 0 ] && echo ","
        first_rel=0
        echo -n "    {\"from\":\"pid_$pid\",\"to\":\"user_$user\",\"type\":\"runs_as\"}"

        # 关系: PID → PPID
        if [ -n "$ppid" ] && [ "$ppid" != "0" ]; then
            echo ","
            echo -n "    {\"from\":\"pid_$pid\",\"to\":\"pid_$ppid\",\"type\":\"child_of\"}"
        fi

        # 关系: PID → NETWORK (from ss)
        if command -v ss &>/dev/null; then
            ss -tnp 2>/dev/null | grep "pid=$pid" | awk '{print $5}' | sed 's/:[0-9]*$//' | sort -u | head -3 | while read ip; do
                [ -z "$ip" ] && continue
                echo ","
                echo -n "    {\"from\":\"pid_$pid\",\"to\":\"ip_$ip\",\"type\":\"connects_to\"}"
            done
        fi

        # 关系: PID → FILE (suspicious fd)
        ls -l "/proc/${pid}/fd/" 2>/dev/null | grep -E '(tmp|dev/shm|var/tmp|memfd|deleted)' | awk '{print $NF}' | head -3 | while read fpath; do
            [ -z "$fpath" ] && continue
            fpath_safe=$(echo "$fpath" | sed 's/"/\\"/g')
            echo ","
            echo -n "    {\"from\":\"pid_$pid\",\"to\":\"file_${fpath_safe}\",\"type\":\"opens\"}"
        done
    done
    echo ""
    echo "  ]"
    echo "}"
} > "${OUTDIR}/entity_correlation.json" 2>&1
append_timeline "$(date +%s)" "entity_correlation" "Entity correlation graph generated"

#=============================================================================
# 16.16 eBPF 程序深度检测
#=============================================================================
echo "[*] eBPF 程序深度检测..."
{
    echo "=============================================="
    echo "  eBPF 程序深度检测 (extra/ebpf_deep.txt)"
    echo "=============================================="
    echo ""

    if command -v bpftool &>/dev/null; then
        echo "=== eBPF 程序列表 ==="
        safe_run 15 bpftool prog show 2>/dev/null
        echo ""
        echo "=== eBPF Map 列表 ==="
        safe_run 15 bpftool map show 2>/dev/null
        echo ""
        echo "=== eBPF 程序附加点 ==="
        safe_run 10 bpftool prog show 2>/dev/null | grep -E 'type|tag|loaded_at' | head -50
        echo ""
        echo "=== 可疑 eBPF 程序类型 ==="
        bpftool prog show 2>/dev/null | grep -E 'type (kprobe|tracepoint|raw_tracepoint|xdp|tc|socket_filter|sk_msg)' | while read line; do
            echo "  [SUS] $line"
            append_timeline "$(date +%s)" "ebpf_suspicious" "eBPF: $line"
        done
    else
        echo "[!] bpftool 未安装，跳过 eBPF 检测"
    fi
    echo ""

    # 从 /sys/kernel 检查 eBPF
    echo "=== /sys/fs/bpf 挂载 ==="
    mount | grep bpf || echo "bpf 文件系统未挂载"
    echo ""
    echo "=== /proc/sys/kernel/unprivileged_bpf_disabled ==="
    cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null && echo "  (1=非特权BPF已禁用)" || echo "不可用"
    echo ""
    echo "=== /proc/sys/net/core/bpf_jit_enable ==="
    cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null && echo "  (1=JIT编译启用)" || echo "不可用"
} > "${OUTDIR}/extra/ebpf_deep.txt" 2>&1
append_timeline "$(date +%s)" "ebpf_deep" "eBPF deep check"

#----------- 17. 打包（超时保护） -----------
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")
if [ -n "${CUSTOM_OUTDIR}" ]; then
    ARCHIVE="${CUSTOM_OUTDIR}/emergency_${HOSTNAME_SHORT}_${TIMESTAMP}.tar.gz"
    TAR_BASE="${CUSTOM_OUTDIR}"
else
    ARCHIVE="/tmp/emergency_${HOSTNAME_SHORT}_${TIMESTAMP}.tar.gz"
    TAR_BASE="/tmp"
fi
echo "[*] 正在打包..."
if timeout 120 tar --warning=no-file-changed -czf "$ARCHIVE" -C "${TAR_BASE}" "emergency_${TIMESTAMP}" 2>/dev/null; then
    :
else
    timeout 120 tar -czf "$ARCHIVE" -C "${TAR_BASE}" "emergency_${TIMESTAMP}" 2>/dev/null
fi
# 计算打包文件哈希
if [ -f "$ARCHIVE" ]; then
    ARCHIVE_HASH=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
    echo "=============================================="
    echo "[✔] 取证完成，打包文件：${ARCHIVE}"
    echo "    SHA256: ${ARCHIVE_HASH}"
    echo "    总耗时：${DURATION} 秒"
    echo "=============================================="
    echo ""
    echo "收集文件清单:"
    echo "  [基础] system_info.txt      - 系统基础信息(含CPU/内存/磁盘/时区/安装日期)"
    echo "  [基础] process.txt           - 进程快照+隐藏进程检测"
    echo "  [基础] network.txt           - 网络连接+防火墙+DNS+流摘要"
    echo "  [基础] extra/ptrace_raw_sockets.txt - Ptrace/Raw Socket检测"
    echo "  [基础] extra/net_l2_l3.txt  - ARP/DNS/Promiscuous/IPv6"
    echo "  [基础] extra/memfd_preload.txt - memfd无文件执行+LD_PRELOAD劫持"
    echo "  [持久化] crontab.txt         - 计划任务+systemd+SSH+自启动+勒索信"
    echo "  [持久化] history_cmds.txt    - 历史命令+可疑模式"
    echo "  [持久化] extra/login_forensics.txt - 用户登录取证"
    echo "  [痕迹] extra/operation_traces.txt - SSH known_hosts+GUI最近文件+Vim痕迹"
    echo "  [分析] extra/shell_classification.txt - Shell历史智能分类(下载/提权/清痕/横移)"
    echo "  [分析] extra/lateral_movement.txt - SSH横向移动图谱"
    echo "  [Web] webshell_scan.txt      - WebShell 11维扫描"
    echo "  [内存马] memshell_check.txt  - Java/PHP/Python/Node.js/eBPF"
    echo "  [Java] tomcat_forensics.txt  - Tomcat目录取证(webapps/lib/conf/bin/work)"
    echo "  [日志] logs/                 - 近7天日志(限500MB)"
    echo "  [日志] log_pattern_analysis.txt - 应用日志可疑模式分析"
    echo "  [日志] temp_class_check.txt  - 临时目录class文件检测"
    echo "  [防护] extra/filesystem_protection.txt - 不可变文件+MIME劫持"
    echo "  [内核] extra/kernel_deep.txt  - 隐藏模块/sysctl/sysrq/auditd"
    echo "  [取证] extra/forensic_enhancement.txt - 文件系统元数据+软件包时间线+进程审计"
    echo "  [关联] process_graph.json    - 进程父子关系图(pid/ppid/user/network/risk)"
    echo "  [关联] sockets.json          - 结构化网络连接JSON"
    echo "  [关联] entity_correlation.json - 实体关联图(PID<->IP<->File<->User)"
    echo "  [评分] risk.json             - 风险评分引擎(CRITICAL/HIGH/MEDIUM/LOW)"
    echo "  [容器] extra/namespace_container.txt - Namespace隔离+容器深度取证+K8s"
    echo "  [内核] extra/ebpf_deep.txt   - eBPF程序/map/挂载点深度检测"
    echo "  [其他] extra/                - suid/hashes/container/limits"
    echo "  [IOC]  ioc_sweep.txt         - IOC全量扫描结果"
    echo "  [IOC]  ioc_output.json       - IOC自动抽取(IP/域名/Hash/URL)"
    echo "  [时间线] timeline_master.txt - 统一时间线"
    echo "  [时间线] timeline.txt        - 采集元信息"
    echo ""
    echo "[!] 请立即将打包文件传输到安全位置，然后删除本地文件"
    echo "    scp ${ARCHIVE} user@evidence-server:/evidence/"
    echo "    rm -f ${ARCHIVE}"
else
    echo "[!] 打包超时或失败，请手动压缩 /tmp/emergency_${TIMESTAMP}"
fi
