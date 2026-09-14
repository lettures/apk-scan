# APK 第三方组件漏洞扫描器（v0.6.x）

按 7 步流程自动化扫描 APK 中的第三方 SDK / 开源组件，并与 NVD CVE 漏洞库比对。**v0.6 重写为"控制台优先 + 静默默认 + 显式开关"**，扫描摘要始终打到终端，进度/全部 SDK 仅在显式传参时显示。

---

## 项目结构

本项目为**单文件交付**——所有功能都打包到一个 `apk_vuln_scan.py` 中（≈129 KB），下载即用：

```
apk_vuln_scan/
├── apk_vuln_scan.py         # 单文件版本（含 7 步流程 + 加固检测 + 终端渲染 + TXT/JSON 输出）
├── README.md                # 本文档
├── .gitignore               # 屏蔽扫描产物、__pycache__/、原始样本、.DS_Store
└── nvd_cache_shared/        # NVD 漏洞缓存（批量扫描复用）
```

`apk_vuln_scan.py` 内部按以下顺序拼接（可见文件头注释）：

| 来源 | 作用 |
|---|---|
| `lib/sdk_signatures.py` | SDK 特征字典（包名/版本正则/类别） |
| `lib/cve_checker.py` | NVD API 客户端（在线 + 离线兜底） |
| `lib/version_fingerprint.py` | 版本指纹 + 类/方法级结构推断 |
| `lib/terminal_renderer.py` | 终端彩色渲染（concise / verbose） |
| `lib/txt_report_builder.py` | 纯文本报告生成器 |
| `detect_hardener.py` | 加固检测器（v10.2 加权打分） |
| `apk_vuln_scan.py` | 主入口（CLI + 7 步编排） |

> 历史版本曾以 `lib/*.py` 多文件形式分发，v0.6 改为单文件部署以方便拷贝分发。如果出于代码审查需要拆分版本，参见 git history。

---

## 7 步流程

| 步骤 | 名称 | 动作 |
|---|---|---|
| 0 | 加固检测 | `detect_hardener.py` v10.2 加权打分；命中加固 → 提示脱壳，未传 `--force` 立即退出（退出码 2） |
| ① | 解压 APK | `unzip target.apk -d workspace/unpacked/`，列出 `lib/<arch>/*.so` |
| ② | 反编译 | 优先 `jadx -d jadx_out target.apk`；缺失时自动用 androguard DEX 字符串扫描兜底 |
| ③ | SDK 识别 | 在反编译源码 / DEX 字符串中搜索包名特征，提取组件名 + 版本号（含版本常量提取、类/方法级结构指纹推断） |
| ④ | 元信息提取 | 解析 `META-INF/` 的 pom.xml / `assets/` 的 gradle 缓存 / `BuildConfig` |
| ⑤ | NVD 比对 | NVD 2.0 API 比对组件 CVE（带磁盘缓存 + 离线兜底） |
| ⑥ | 高危专项 | 加密 / 网络 / WebView / 序列化四大类历史 CVE 专项核查 |
| ⑦ | 渲染输出 | TerminalRenderer 始终打印；按 `--output` 决定是否落盘 JSON / TXT |

---

## 安装依赖

```bash
/Users/wang/.workbuddy/binaries/python/envs/default/bin/pip install androguard requests
# 系统：unzip（必需）；jadx（可选，缺失时自动用 androguard 兜底）
```

---

## 用法

### 最简：默认静默 + 只看问题组件 + 控制台输出

```bash
python3 apk_vuln_scan.py
```

- 进度日志：静默（仅 FAIL / STEP / OK 显示）
- 终端：仅打印存在问题的 SDK（弱证据与 AOSP 框架库默认隐藏）
- 文件：不写
- 退出码：`0`（无风险）或 `2`（命中 CVE / 加固拦截 / 致命错误）

### 静默脱壳目录扫描

```bash
python3 apk_vuln_scan.py --input-dir ./unpacked_dex_dir
```

### 加固样本强行扫描

```bash
python3 apk_vuln_scan.py cimoc.apk --force
```

> ⚠️ 加固样本会大量漏报（DEX 字符串被加密），仅在"评估加固厂商 SDK"或"确认需要原始数据"时使用。

### 显示全部 SDK（不只问题组件）

```bash
python3 apk_vuln_scan.py --all-sdks
```

### 显示完整进度日志

```bash
python3 apk_vuln_scan.py --verbose          # 或 -v
python3 apk_vuln_scan.py --verbose --all-sdks
```

### 输出 JSON 文件

```bash
python3 apk_vuln_scan.py --output json
# 落盘：与脚本同目录 <apk_name>_vuln.json
```

### 输出 TXT 文件（合规场景首选）

```bash
python3 apk_vuln_scan.py --output txt
# 落盘：与脚本同目录 <apk_name>_vuln.txt
```

TXT 报告纯文本、可 `grep`、可直接 `cat` 查看，无需浏览器。

### 输出到自定义目录

```bash
python3 apk_vuln_scan.py --output json --output-dir ./out/v1
```

### 指定 jadx 路径

```bash
python3 apk_vuln_scan.py --jadx /opt/homebrew/bin/jadx
# 也可用 JADX= 环境变量
```

### 批量场景：共享 NVD 缓存

```bash
python3 apk_vuln_scan.py a.apk --nvd-cache-dir ./nvd_cache_shared
python3 apk_vuln_scan.py b.apk --nvd-cache-dir ./nvd_cache_shared
# 同一份缓存复用，避免重复网络请求
```

### 组合：对脱壳目录 + 全部 SDK + JSON + 完整日志

```bash
python3 apk_vuln_scan.py --input-dir ./unpacked \
    --all-sdks --verbose --output json --output-dir ./out
```

---

## CLI 参数速查

| 参数 | 别名 | 默认 | 含义 |
|---|---|---|---|
| `apk` | — | 必填 | 目标 APK 路径；与 `--input-dir` **二选一** |
| `--input-dir` | — | — | 已脱壳 / 已解压目录（跳过 unzip） |
| `--jadx` | — | 自动查找 | jadx 可执行文件路径 |
| `--source-dir` | — | 自动识别 | 已反编译源码目录（跳过 ②） |
| `--nvd-key` | — | — | NVD API Key（推荐） |
| `--work-dir` | — | `./workspace` | 工作目录 |
| `--output-dir` | — | 与脚本同目录 | 文件输出目录（`--output ≠ console` 时生效），不传则与 py 文件同级 |
| `--no-cleanup` | — | False | 保留工作目录 |
| `--aggressive-estimate` | — | False | 允许结构推断版本去查 CVE（推断值是区间，可能产生虚假命中） |
| `--force` | — | False | 跳过加固检测（高风险） |
| `--nvd-cache-dir` | — | 本次独立 | NVD 漏洞缓存目录 |
| **`--output`** | — | `console` | 输出形式：`console` / `json` / `txt` |
| **`--verbose`** | `-v` | False | 显示进度日志（INFO/STEP/OK） |
| **`--all-sdks`** | — | False | 显示全部 SDK（含证据不足） |

> `--report-dir` 已废弃，统一改为 `--output-dir`。

---

## 输出

控制台**始终**打印扫描摘要（verdict / 命中 SDK / 命中 CVE），与 `--output` 选项无关。

按 `--output` 决定是否额外落盘：

| `--output` | 控制台 | 落盘文件（默认与脚本同目录） |
|---|---|---|
| `console`（默认） | ✓ | 无 |
| `json` | ✓ | `./<apk_name>_vuln.json` |
| `txt` | ✓ | `./<apk_name>_vuln.txt` |

JSON 字段：`summary`、`sdks[]`（精简字段，删除干扰项）、`cves[]`、`high_risk_findings[]`、`hardener{}`、`meta{}`。
TXT 字段：纯文本分段（文件头、基础信息、加固状态、SDK 列表、CVE 列表、高危发现、附录）。

---

## 工作目录生命周期（默认行为：只剩结果）

扫描运行时产物（默认生命周期）：

```
┌─ 扫描开始 ──────────────────────────────────────────────────────┐
│  ./workspace/                  ← 临时工作区（每个扫描独立子目录）
│    ├─ extracted/                ← APK 解压（unzip）
│    ├─ jadx_out/  或 jadx_fallback/  ← jadx 反编译产物（可达数百 MB）
│    ├─ dex_strings.txt           ← DEX 字符串提取（1-2 MB）
│    └─ nvd_cache/                ← NVD 漏洞缓存（每次扫描独立）
└─────────────────────────────────────────────────────────────────┘
┌─ 扫描结束 ──────────────────────────────────────────────────────┐
│  ./workspace/                  ← 已自动清理（shutil.rmtree）
│  ./<apk_name>_vuln.{json,txt}  ← 唯一留存的最终结果
└─────────────────────────────────────────────────────────────────┘
```

| 开关 | 行为 |
|---|---|
| **默认**（无 `--no-cleanup`） | 扫描结束自动 `rm -rf workspace/`，**仅留结果** |
| `--no-cleanup` | 保留 `workspace/` 用于排查（debug / 看 jadx 反编译产物） |
| `--input-dir <dir>` | 不清理（输入即用户原始数据，不动） |

**典型场景产物体积**：

| 场景 | `workspace/` 体积 | 是否需要清理 |
|---|---|---|
| 单 APK 扫描（默认） | 30 ~ 数百 MB（取决于 jadx 反编译产物） | 自动清理 |
| 目录批量（`--input-dir`） | 0（不创建临时目录） | 不需要 |
| 加固强行扫描（`--force`） | 同上（不依赖 jadx 反编译产物） | 自动清理 |

**结论**：日常使用无需关心 `workspace/`——它会在扫描结束时自动清空。如果要"清理中间产物"，什么都不用做，默认就是最干净的。

### 清理保证（三层兜底）

| 兜底层 | 触发场景 | 行为 |
|---|---|---|
| `finally` 块 `shutil.rmtree` | 正常扫描结束 | `rm -rf workspace/`，**WARN 日志**（清理失败时告知用户） |
| SIGINT / SIGTERM 信号处理 | `Ctrl+C` 中断扫描 / `kill <pid>` | **同步触发清理**，再抛 `KeyboardInterrupt` 让 `finally` 正常退出（Unix 约定退出码 130） |
| `--no-cleanup` 显式开关 | 用户主动保留中间产物排查 | 跳过清理（不推荐用于生产） |

**与 .gitignore 的关系**：本项目**不依赖 .gitignore**——`shutil.rmtree` + 信号处理让"运行时产物在生成结果后删除"这件事 100% 可靠，仓库中只会有 `apk_vuln_scan.py` + `README.md` + 你主动指定的报告文件。

---

## 终端 / 文件过滤策略

| 维度 | 默认 | `--all-sdks` | 说明 |
|---|---|---|---|
| `weak_evidence=True` | 过滤 | **保留** | 证据不足（仅字符串残留、类索引兜底过弱） |
| `is_android_framework_lib=True` | 过滤 | **保留** | AOSP 系统库（androidx / com.google.android.material 等） |
| 加固场景 `is_packed=True` | **强制保留全部** | — | 用于评估加固厂商 SDK，不可过滤 |

---

## 判定逻辑

| 判定 | 条件 |
|---|---|
| `RISK` | 至少 1 个第三方组件命中已知 CVE **或** 任一高危类别命中 |
| `CLEAN` | 未发现已知 CVE（不代表 0 漏洞，仍需人工复核） |

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 扫描成功，无致命问题（verdict 可能是 RISK 或 CLEAN） |
| `2` | 加固拦截未脱壳 / `--force` 也未加但仍要给提示 / 致命错误（输入不存在、参数缺失、不可恢复） |

---

## 加固样本处理流程

```
扫描 APK
  │
  ├── detect_hardener.py v10.2 加权打分
  │     │
  │     ├── 命中加固（is_packed=True）
  │     │     ├── 提示 3 步建议（脱壳 → 重扫 → 或 --force）
  │     │     ├── 未传 --force → 立即退出（退出码 2）
  │     │     └── 传了 --force → is_packed 标记为 True，继续扫描
  │     │
  │     └── 未命中加固
  │           └── 正常进入步骤 ①②③④⑤⑥⑦
  │
  └── 注：is_packed=True 时 --all-sdks 强制为 True（不漏看加固厂商 SDK）
```

---

## 注意事项

1. **加壳 / 混淆样本**：jadx 兜底模式只能扫到 DEX 中的字符串，混淆或加固样本大量特征会漏报。建议先用 Fdex / FART / BlackDex 脱壳后用 `--input-dir` 重扫。
2. **NVD 速率限制**：无 key 时 5 次 / 30 秒，有 key 时 50 次 / 30 秒。脚本内置节流 + 磁盘缓存；批量场景建议传 `--nvd-cache-dir` 共享缓存。
3. **离线模式**：网络不可用时自动回退到内置 CVE 表（覆盖 OkHttp / Retrofit / Fastjson / Gson / Jackson / OpenSSL / BouncyCastle 等关键历史 CVE）。
4. **macOS TCC**：jadx 位于未授权目录时可能被 TCC 拦截（Operation not permitted）。详见「如何连接 jadx → 4. macOS TCC 拦截」章节。
5. **结构推断版本**：`--aggressive-estimate` 放行结构指纹推断的版本，值是区间而非精确版本，开启可能产生虚假命中，结果需人工复核。

---

## 如何连接 jadx

本扫描器的核心流程是「DEX 反编译 → SDK 识别 → CVE 比对」，其中**反编译**这一环依赖 jadx。jadx 集成有三种粒度：CLI 自动调用 / 手动反编译复用 / jadx-gui 配套插件定位，按需选择。

### 1. CLI 自动调用（本工具内部使用）

扫描器内置 jadx 路径解析，按以下顺序自动查找，**无需任何配置**即可在 99% 的场景下工作：

```
优先级（高 → 低）
  1. --jadx /path/to/jadx   命令行显式参数
  2. JADX=/path/to/jadx     环境变量
  3. PATH 上的 jadx          shutil.which("jadx")
  4. 内置候选路径            常见安装位（见下）
```

内置候选路径（按顺序查找）：

| 路径 | 说明 |
|---|---|
| `~/Desktop/app/测试工具/jadx-1.5.6/bin/jadx` | 本地开发机首选 |
| `~/Desktop/app/jadx/bin/jadx` | 同上，通用版本号 |
| `/opt/jadx/bin/jadx` | Linux 标准位置 |
| `/usr/local/jadx/bin/jadx` | macOS Homebrew 兼容位置 |
| `~/.workbuddy/tools/jadx/bin/jadx` | WorkBuddy 工具目录（推荐） |

```bash
# 方式 A：命令行参数（最直接）
python3 apk_vuln_scan.py --jadx /opt/homebrew/bin/jadx

# 方式 B：环境变量（推荐 CI / 批量场景）
export JADX=/opt/homebrew/bin/jadx
python3 apk_vuln_scan.py

# 方式 C：让 jadx 进 PATH
which jadx && python3 apk_vuln_scan.py
```

**缺失时自动兜底**：找不到 jadx 时扫描器不会报错，而是用 androguard 直接读取 DEX 字符串。优点是无依赖，缺点是反编译产物只剩包名，看不到类/方法级细节（v0.5+ 已加 `class_def` 兜底以补充类索引）。

### 2. 手动反编译后复用（推荐：分析单个样本）

适合需要人工确认反编译结果的场景。先用 jadx 反编译，再把源码目录直接喂给扫描器，跳过步骤 ②：

```bash
# 步骤 1：手动反编译（可以调 jadx 参数，如 --no-res 跳过资源加速）
jadx -d ./jadx_out --no-res target.apk

# 步骤 2：直接传入源码目录
python3 apk_vuln_scan.py --source-dir ./jadx_out/sources
# 也可直接传已脱壳目录：
python3 apk_vuln_scan.py --input-dir ./jadx_out/sources
```

优势：

- 跳过 unzip + jadx 调用，秒级启动
- 调试时让 jadx 跑 `--no-imports --no-debug-info` 等不同参数
- 已反编译过的 APK 用 `--source-dir` 复用上次产物

### 3. 与 jadx-gui 插件「核心代码定位器」协同（推荐：定位漏洞核心代码）

扫描器告诉你「哪个 SDK 的哪个版本命中了 CVE」，jadx-gui 插件帮你「在反编译代码中跳转到该 SDK 的核心实现行」。两者是 CVE 比对 → 代码定位的上下游关系。

工作流：

```bash
# 步骤 1：扫描器识别有问题 SDK
python3 apk_vuln_scan.py --output json
# → 脚本同目录 target_vuln.json 里能看到命中的 SDK 列表 + 版本 + CVE

# 步骤 2：用 jadx-gui 打开同一份 APK（不要打开 *.apk.jadx 项目文件！）
jadx-gui target.apk
#   ↓ 菜单栏 → Plugins → 核心代码定位器（core-code-locator）
#   ↓ 输入步骤 1 中命中的 SDK 包名 / 关键字符串（如 "okhttp3.OkHttpClient"）
#   ↓ 插件直接跳转到该 SDK 在反编译代码中的具体行
```

⚠️ **第一铁律**：插件结果不对时，先确认 jadx-gui 当前打开的是 `target.apk`（MB 级），而不是 `target.apk.jadx` 项目文件（KB 级，是 JSON）。详细排障见 [`jadx-plugin-dev` skill](../..)（~/.workbuddy/skills/jadx-plugin-dev）。

### 4. macOS TCC 拦截（首次失败的常见原因）

jadx 装在 `/opt/homebrew/bin/` 或 `~/Desktop/...` 时，macOS 可能弹出「Operation not permitted」错误（不让执行）：

```bash
# 症状：jadx 命令存在但执行时报 TCC 拒绝
ls -la /opt/homebrew/bin/jadx           # 文件在
/opt/homebrew/bin/jadx --version       # 但执行失败

# 解决办法（按优先级）：
# 方案 1：复制到 WorkBuddy 工具目录（推荐）
mkdir -p ~/.workbuddy/tools/jadx/bin
cp /opt/homebrew/bin/jadx ~/.workbuddy/tools/jadx/bin/
~/.workbuddy/tools/jadx/bin/jadx --version

# 方案 2：在「系统设置 → 隐私与安全性 → 完全磁盘访问权限」授权终端
# （iTerm2 / Terminal.app / VS Code 终端都要分别授权）

# 方案 3：先用 --jadx 参数显式指定一个已授权路径
python3 apk_vuln_scan.py --jadx ~/.workbuddy/tools/jadx/bin/jadx
```

### 5. 完整工作流：扫描 → 定位 → 复核

```
┌─────────────────────────────┐
│ ① 扫描器识别有 CVE 的 SDK    │    apk_vuln_scan.py --output json
│    输出 sdks[].name/cves[]  │
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ ② jadx-gui 打开同一份 APK   │    jadx-gui target.apk
│    插件「核心代码定位器」搜索 │    插件输入 ① 中命中的包名/关键类
└─────────┬───────────────────┘
          │
          ▼
┌─────────────────────────────┐
│ ③ 直接跳转到反编译代码行     │    插件：row-level 精确跳转（如 URL 字符串所在行）
│    人工复核 + 整改           │
└─────────────────────────────┘
```

---

## 扩展自定义 SDK

在 `lib/sdk_signatures.py` 的 `SDK_SIGNATURES` 字典中添加新条目：

```python
"MySDK": {
    "category": "network",
    "package_pattern": re.compile(r"com[/\\]example[/\\]mysdk"),
    "version_hints": [r"mysdk[-/ ](\d+\.\d+\.\d+)"],
    "homepage": "https://example.com",
}
```

---

## 版本历史

| 版本 | 日期 | 要点 |
|---|---|---|
| v0.6.x | 2026-09 | CLI 控制台优先 / 默认静默 / `--verbose` + `--all-sdks` 显式开关；输出仅 console / json / txt（删除 HTML）；加固检测 step0 + `--force`；退出码语义化；TerminalRenderer 双模式（concise / verbose） |
| v0.5.x | 2026-09 | DEX class_def 兜底 / 精简 JSON / 终端彩色渲染 / 去掉整改建议 |
| v0.4.x | 2026-09 | NVD 2.0 + 离线兜底 / 4 类专项核查 / 高危类别告警 |

---

## 相关技能与工具

- `apk-static-scan`（全局 Skill）：androguard 静态安全扫描器（用于检测 Manifest 配置 / 加固识别 / DEX 字符串规则 / ELF/资产文件检查）
- jadx-gui 插件「核心代码定位器」`core-code-locator` v0.5.9：DEX 反编译代码中的核心代码搜索能力
