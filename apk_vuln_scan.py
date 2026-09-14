#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK 第三方组件漏洞扫描器（v0.6）- 单文件版
==========================================

本文件由原 7 个模块合并而来：
  - lib/sdk_signatures.py      SDK 特征字典（包名/版本正则/类别）
  - lib/cve_checker.py         NVD 客户端（在线 + 离线兜底）
  - lib/version_fingerprint.py 版本指纹 + 结构推断
  - lib/terminal_renderer.py   终端彩色渲染
  - lib/txt_report_builder.py  纯文本报告生成器
  - detect_hardener.py         加固检测器（v10.2 加权打分）
  - scan_apk_vuln.py           主入口（CLI + 7 步编排）

合并动机：方便下载分发（单个文件即可运行）+ 减少部署摩擦。

依赖：
  pip install androguard requests
  系统：unzip（必需）；jadx（可选）

用法：
  python3 apk_vuln_scan.py <target.apk>
  python3 apk_vuln_scan.py --help
"""

from __future__ import annotations

# ===== 文件级 imports（来自各模块） =====
# 标准库
import re
from pathlib import Path
import hashlib
import json
import time
from typing import Any
from dataclasses import dataclass, field
import os
import sys
from datetime import datetime
import argparse
import zipfile
from collections import defaultdict
import shutil
import signal
import subprocess

# ==============================================================================
# 模块：lib/sdk_signatures.py
# ==============================================================================

# 统一包路径分隔符（点 / 正斜杠 / 反斜杠 任一）
SE = r"[\./\\]"

# ----------------------------------------------------------------------
# Android Framework / 系统库路径前缀
# ----------------------------------------------------------------------
# 这些路径属于 Android Framework 内置（AOSP 编译时合并进 framework.jar），
# 不属于 App 自身的 Maven 依赖。其版本与设备 Android 版本绑定，与 App 无关，
# 即使 App 升级也无法替换它们 —— 因此不参与第三方依赖 CVE 判定。
#
# 命中规则（保守）：
#   - 任一完整类引用命中以下 hint → 视为 framework 集成
#   - xx-prefix 截断匹配不算（无法确认完整路径）
#   - 实际逻辑：在 step3 中，若 SDK 的所有完整类引用都是 framework 路径，
#     或 framework 占比 >= 80%，则标记为 framework。
#
# 常见路径：
#   - com.android.*（AOSP 改名前缀，如 com.android.okhttp.* / com.android.org.conscrypt.*）
#   - android.net.connectivity.org.chromium.*（AOSP 网络层 Chromium）
#   - android.app.*（AOSP App 框架）
#   - org.xml.sax.*（JDK 标准 SAX 接口）
#   - org.w3c.dom.*（JDK W3C DOM 接口）
#   - javax.xml.*（JDK JAXP 接口）
#   - org.apache.xalan.* / org.apache.xerces.* / org.apache.xml.*（AOSP 编译进 framework 的 Apache XML 实现）
ANDROID_FRAMEWORK_PATH_HINTS: list[str] = [
    r"Lcom[./\\]android[./\\]",
    r"Landroid[./\\]net[./\\]connectivity[./\\]org[./\\]chromium[./\\]",
    r"Landroid[./\\]app[./\\]",
    r"Lorg[./\\]xml[./\\]sax[./\\]",
    r"Lorg[./\\]w3c[./\\]dom[./\\]",
    r"Ljavax[./\\]xml[./\\]",
    # AOSP 编译进 framework 的 Apache XML 库（org.apache.xalan.* / org.apache.xerces.* / org.apache.xml.*）
    # 注意：[./\\]? 让截断形式也能匹配（如 "Lorg.apache.xerces" 无后缀字符）
    r"Lorg[./\\]apache[./\\](?:xalan|xerces|xml)(?:[./\\]|$)",
    # 截断形式（xx 前缀）专用：仅匹配包名级别（不需要后续分隔符）
    r"^xx(?:org[./\\]apache[./\\](?:xalan|xerces|xml)|com[./\\]android|org[./\\]xml[./\\]sax|org[./\\]w3c[./\\]dom|javax[./\\]xml|android[./\\]net[./\\]connectivity[./\\]org[./\\]chromium)",
]

def is_android_framework_path(class_ref: str) -> bool:
    """判定一个类引用是否属于 Android Framework 系统库。

    参数 class_ref：完整类引用字符串（如 'Lcom/android/okhttp/Connection;'），
                   或字符串池中的非类引用形式（如 'org.apache.xerces.framework.Version'，
                   标记为 'xx' 前缀的截断匹配）

    返回 True 表示该引用指向 Android Framework 内置类，App 无法替换其版本。
    """
    if class_ref.startswith("xx"):
        # 截断标记：直接基于字符串内容判定（去掉 xx 前缀）
        content = class_ref[2:]
    else:
        content = class_ref

    for hint in ANDROID_FRAMEWORK_PATH_HINTS:
        # 注意：hint 里写的是 Lcom/... 形式；对 xx- 截断匹配要去掉 L 前缀再匹配
        # 简化处理：把 content 补一个 L 前缀再匹配
        check = content if content.startswith("L") else "L" + content
        if re.search(hint, check):
            return True
        # 也直接匹配（针对已经不带 L 的字符串池内容）
        if re.search(hint.replace(r"L", "", 1), content):
            return True
    return False

def is_mostly_android_framework(refs: list[str], threshold: float = 0.8) -> bool:
    """判定一组类引用是否主要是 Android Framework 系统库。

    参数：
      refs: 完整类引用或字符串池内容（xx- 截断形式也接受）
      threshold: framework 占比阈值（默认 0.8 = 80%）

    返回：True 表示该 SDK 在当前 APK 中主要是 framework 集成。

    处理逻辑：
      - 完整类引用（L 前缀）：按前缀 + 内容判定
      - xx- 截断形式：基于字符串内容本身判定（去掉 xx 前缀）
      - 两者都计入 framework 占比统计
    """
    if not refs:
        return False
    fw_count = sum(1 for r in refs if is_android_framework_path(r))
    return (fw_count / len(refs)) >= threshold

# ----------------------------------------------------------------------
# SDK 特征签名
# ----------------------------------------------------------------------

SDK_SIGNATURES: dict[str, dict] = {
    # ---------------- 网络层 ----------------
    "OkHttp": {
        "category": "network",
        # 兼容 okhttp3.*（4.x 主流）和 okhttp.*（2.x 老版本 / 部分发行版去掉 "3" 前缀）
        "package_pattern": re.compile(r"\bokhttp(?:3)?" + SE),
        "version_hints": [r"okhttp(?:3)?[/ ](\d+\.\d+\.\d+)"],
        # DEX 全局扫描：User-Agent / log 格式 / Maven artifact 名称
        "global_version_patterns": [
            r"okhttp[/ ](\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
            r"OkHttp[/ ](\d+\.\d+\.\d+)",
            r"okhttp3?[-_](\d+\.\d+\.\d+)",
        ],
        # jadx 源码兜底：源码注释中的版本、Version 类的 VERSION 常量、
        # getOkHttpClient 内部 "Release_4_9_0" 风格的 tag 字段
        "jadx_version_patterns": [
            # 注释行：// OkHttp version 4.9.0 / * okhttp 3.12.1 *
            r"//\s*(?:OkHttp|okhttp)\s+version\s+(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
            r"//\s*Version\s+(\d+\.\d+\.\d+)",
            # Version 类常量：public static final String VERSION = "4.9.0"
            r'public\s+static\s+final\s+String\s+VERSION\s*=\s*"(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)"',
            # build 字段：String VERSION = "okhttp/4.9.0"
            r'RELEASE[^"]*"(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)"',
            # Git tag 风格：RELEASE_4_9_0
            r"RELEASE[_-](\d+[._]\d+[._]\d+)",
            # META-INF/MANIFEST.MF 中的 Implementation-Version
            r"Implementation-Version:\s*(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
        ],
        # jadx 源码作用域：只在这些目录里搜。
        # 必须有！否则像 `VERSION = "x.y.z"` 这种不带 SDK 名的通用模式，
        # 会在全库 7000+ 文件中命中第一个无关文件（v9 修复的 bug）。
        "jadx_package_dirs": [
            "com/android/okhttp/",   # AOSP 内置 fork
            "com/squareup/okhttp",   # 官方 Maven 依赖
            "okhttp3/",              # 3.x/4.x 根目录
            "okhttp/",               # 2.x 根目录
        ],
        "homepage": "https://square.github.io/okhttp/",
    },
    "Retrofit": {
        "category": "network",
        "package_pattern": re.compile(r"retrofit2" + SE),
        "version_hints": [r"retrofit2[/\\](\d+\.\d+\.\d+)"],
        "global_version_patterns": [
            r"Retrofit(?:2)?[/ ](\d+\.\d+\.\d+)",
            r"retrofit-android[/ ](\d+\.\d+\.\d+)",
            r"retrofit2?[-_](\d+\.\d+\.\d+)",
        ],
        # 源码作用域（必需）。缺了它，版本常量提取会退化成全库扫描，
        # 把别的库的版本（实测曾把 Jackson 的 2.8.7）错配到 Retrofit 头上。
        "jadx_package_dirs": [
            "retrofit2/",                # 主包（Retrofit 2.x）
            "com/squareup/retrofit2/",   # 少数发行版路径
        ],
        "homepage": "https://square.github.io/retrofit/",
    },
    "okio": {
        "category": "network",
        "package_pattern": re.compile(r"\bokio" + SE),
        "version_hints": [r"okio[/ ](\d+\.\d+\.\d+)"],
        "global_version_patterns": [
            r"\bokio[/ ](\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
            r"\bokio[-_](\d+\.\d+\.\d+)",
        ],
        "jadx_version_patterns": [
            r"//\s*Okio\s+version\s+(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
            r"//\s*Version\s+(\d+\.\d+\.\d+)",
            r'public\s+static\s+final\s+String\s+VERSION\s*=\s*"(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)"',
            r'RELEASE[^"]*"(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)"',
            r"RELEASE[_-](\d+[._]\d+[._]\d+)",
            r"Implementation-Version:\s*(\d+\.\d+\.\d+(?:[-+][a-z0-9.]+)?)",
        ],
        "jadx_package_dirs": [
            "com/android/okhttp/okio/",  # AOSP 内置（okio 被打进 okhttp 包）
            "com/squareup/okio",
            "okio/",
        ],
        "homepage": "https://github.com/square/okio",
    },
    "Chromium net (Cronet/WebView)": {
        "category": "network",
        # Conscrypt 底层使用 Chromium net / base 栈；WebView/Cronet/Chrome Custom Tabs 也都带 org.chromium.*
        "package_pattern": re.compile(r"org" + SE + r"chromium" + SE + r"(?:net|base|build|mojo|url)"),
        "version_hints": [r"chromium[/ ](\d+\.\d+\.\d+)"],
        # 优先级：
        # 1. 4 段版本号带 Chrome/Chromium/Cronet/Conscrypt 前缀（最可靠）
        # 2. 4 段版本号独立出现（需通过 is_chromium_version 验证过滤 IP）
        # 3. SPDY 协议版本（间接 marker）
        "global_version_patterns": [
            r"Chrome[/ ](\d{2,3}\.\d{1,3}\.\d{1,5}\.\d{1,5})",
            r"Chromium[/ ](\d{2,3}\.\d{1,3}\.\d{1,5}\.\d{1,5})",
            r"Cronet[/ ](\d{2,3}\.\d{1,3}\.\d{1,5}\.\d{1,5})",
            r"Conscrypt[/ ](\d+\.\d+\.\d+\.\d+)",
            # 独立 4 段版本号（验证器过滤 IP）
            r"(?<!\d)(\d{2,3}\.\d{1,3}\.\d{1,5}\.\d{1,5})(?!\d)",
            # spdy/3.1 是协议版本而非浏览器版本，但可作为存在性 marker
            r"spdy[/ ](\d+\.\d+)",
        ],
        "global_version_validators": ["is_chromium_version"],
        "homepage": "https://chromium.googlesource.com/",
    },
    "Volley": {
        "category": "network",
        "package_pattern": re.compile(r"com" + SE + r"android" + SE + r"volley"),
        "version_hints": [],
        "homepage": "https://google.github.io/volley/",
    },
    "Apache HttpClient": {
        "category": "network",
        "package_pattern": re.compile(r"org" + SE + r"apache" + SE + r"http"),
        "version_hints": [],
        "homepage": "https://hc.apache.org/",
    },

    # ---------------- 图片 / 多媒体 ----------------
    "Glide": {
        "category": "image",
        "package_pattern": re.compile(r"com" + SE + r"bumptech" + SE + r"glide"),
        "version_hints": [r"glide[/ ]v?(\d+\.\d+\.\d+)"],
        "jadx_package_dirs": ["com/bumptech/glide/"],
        "homepage": "https://github.com/bumptech/glide",
    },
    "Picasso": {
        "category": "image",
        "package_pattern": re.compile(r"com" + SE + r"squareup" + SE + r"picasso"),
        "version_hints": [r"picasso[/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://square.github.io/picasso/",
    },
    "Fresco": {
        "category": "image",
        "package_pattern": re.compile(r"com" + SE + r"facebook" + SE + r"fresco"),
        "version_hints": [r"fresco[/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://frescolib.org/",
    },

    # ---------------- JSON 序列化 ----------------
    "Fastjson": {
        "category": "serialize",
        "package_pattern": re.compile(r"com" + SE + r"alibaba" + SE + r"fastjson"),
        "version_hints": [r"fastjson[/ ]?v?(\d+\.\d+\.\d+)"],
        # Fastjson 在 JSON.java 里有 VERSION 常量：
        #   public static final String VERSION = "1.1.46";   ← 1.1.x 系列（阿里 fork）
        #   public static final String VERSION = "1.2.83";   ← 1.2.x 系列（官方主线）
        # 这两个分支的 CVE 不同，需要分别查。
        "jadx_version_patterns": [
            r'public\s+static\s+final\s+String\s+VERSION\s*=\s*"(\d+\.\d+\.\d+(?:\.\d+)?)"',
        ],
        "jadx_package_dirs": [
            "com/alibaba/fastjson/",
        ],
        "homepage": "https://github.com/alibaba/fastjson",
    },
    "Gson": {
        "category": "serialize",
        "package_pattern": re.compile(r"com" + SE + r"google" + SE + r"gson"),
        "version_hints": [r"gson[/ ](\d+\.\d+\.\d+)"],
        # Gson 产物里没有任何版本字符串（实测 global/源码/常量三种手段均为 0 命中），
        # 版本只能由结构指纹推断（见 lib/version_fingerprint.py）。
        "jadx_package_dirs": ["com/google/gson/"],
        "homepage": "https://github.com/google/gson",
    },
    "Jackson": {
        "category": "serialize",
        "package_pattern": re.compile(r"com" + SE + r"fasterxml" + SE + r"jackson"),
        "version_hints": [r"jackson[-/ ](\d+\.\d+\.\d+)"],
        # jackson-core 自带 com/fasterxml/jackson/core/json/PackageVersion.java，
        # 其中写着 VersionUtil.parseVersion("2.8.7", ...) —— 可直接读出精确版本。
        "jadx_package_dirs": ["com/fasterxml/jackson/"],
        "homepage": "https://github.com/FasterXML/jackson",
    },

    # ---------------- 加密 ----------------
    "BouncyCastle": {
        "category": "crypto",
        "package_pattern": re.compile(r"org" + SE + r"bouncycastle"),
        "version_hints": [r"bcprov[-/ ]?jdk?\d+?[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://www.bouncycastle.org/",
    },
    "Conscrypt": {
        "category": "crypto",
        "package_pattern": re.compile(r"org" + SE + r"conscrypt"),
        "version_hints": [r"conscrypt[/ ](\d+\.\d+\.\d+)"],
        # Conscrypt 包含 BoringSSL（X.Y.Z-dev 格式）
        "global_version_patterns": [
            r"Conscrypt[/ ](\d+\.\d+\.\d+(?:\.\d+)?)",
            r"Conscrypt version[: ]+(\d+\.\d+\.\d+(?:\.\d+)?)",
            r"(?<!\d)(\d{1,2}\.\d{1,3}\.\d{1,3})-dev(?!\d)",  # BoringSSL
            r"\bConscrypt (\d+\.\d+\.\d+(?:\.\d+)?)\b",
        ],
        "homepage": "https://github.com/google/conscrypt",
    },
    "OpenSSL (native)": {
        "category": "crypto",
        "package_pattern": re.compile(r"libcrypto|libssl"),
        "version_hints": [r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)"],
        "homepage": "https://www.openssl.org/",
    },
    "SpongyCastle": {
        "category": "crypto",
        "package_pattern": re.compile(r"com" + SE + r"madv313" + SE + r"spongycastle"),
        "version_hints": [],
        "homepage": "https://github.com/mrintolerant/SpongyCastle",
    },

    # ---------------- WebView / JS 桥 ----------------
    "JSBridge": {
        "category": "webview",
        "package_pattern": re.compile(r"com" + SE + r"github" + SE + r"lzyzsd" + SE + r"jsbridge"),
        "version_hints": [],
        "homepage": "https://github.com/lzyzsd/JSBridge",
    },
    "Cordova": {
        "category": "webview",
        "package_pattern": re.compile(r"org" + SE + r"apache" + SE + r"cordova"),
        "version_hints": [r"cordova[/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://cordova.apache.org/",
    },

    # ---------------- 推送 / 统计 ----------------
    "Firebase": {
        "category": "push",
        "package_pattern": re.compile(r"com" + SE + r"google" + SE + r"firebase"),
        "version_hints": [r"firebase[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://firebase.google.com/",
    },
    "JPush": {
        "category": "push",
        "package_pattern": re.compile(r"cn" + SE + r"jpush" + SE + r"android"),
        "version_hints": [r"jpush[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://www.jpush.cn/",
    },
    "Getui": {
        "category": "push",
        "package_pattern": re.compile(r"com" + SE + r"igexin"),
        "version_hints": [r"getui[-/ ]sdk?[-/ ]?(\d+\.\d+\.\d+)"],
        "homepage": "https://www.getui.com/",
    },
    "Umeng": {
        "category": "analytics",
        "package_pattern": re.compile(r"com" + SE + r"umeng" + SE),
        "version_hints": [r"umeng[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://www.umeng.com/",
    },
    "Bugly": {
        "category": "analytics",
        "package_pattern": re.compile(r"com" + SE + r"tencent" + SE + r"bugly"),
        "version_hints": [r"bugly[-/ ]?(\d+\.\d+\.\d+)"],
        "homepage": "https://bugly.qq.com/",
    },
    "Umeng Push": {
        "category": "push",
        "package_pattern": re.compile(r"com" + SE + r"umeng" + SE + r"message"),
        "version_hints": [],
        "homepage": "https://www.umeng.com/",
    },

    # ---------------- 腾讯系 ----------------
    "Tencent IMSDK": {
        "category": "im",
        "package_pattern": re.compile(r"com" + SE + r"tencent" + SE + r"imsdk"),
        "version_hints": [r"imsdk[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://cloud.tencent.com/product/im",
    },
    "QQ Login": {
        "category": "social",
        "package_pattern": re.compile(r"com" + SE + r"tencent" + SE + r"connect"),
        "version_hints": [],
        "homepage": "https://connect.qq.com/",
    },
    "WeChat Open Platform": {
        "category": "social",
        "package_pattern": re.compile(r"com" + SE + r"tencent" + SE + r"mm" + SE + r"sdk"),
        "version_hints": [r"wechat[-/ ]?(\d+\.\d+\.\d+)"],
        "homepage": "https://open.weixin.qq.com/",
    },

    # ---------------- 阿里系 ----------------
    "Alipay SDK": {
        "category": "payment",
        "package_pattern": re.compile(r"com" + SE + r"alipay" + SE + r"sdk"),
        "version_hints": [r"alipay[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://open.alipay.com/",
    },

    # ---------------- 字节系 ----------------
    "ByteDance SDK": {
        "category": "analytics",
        "package_pattern": re.compile(r"com" + SE + r"bytedance"),
        "version_hints": [r"bytedance[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://oceanengine.com/",
    },

    # ---------------- 地图 / 定位 ----------------
    "Amap": {
        "category": "location",
        "package_pattern": re.compile(r"com" + SE + r"amap" + SE + r"api"),
        "version_hints": [r"amap[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://lbs.amap.com/",
    },
    "Baidu Map": {
        "category": "location",
        "package_pattern": re.compile(r"com" + SE + r"baidu" + SE + r"mapapi|com" + SE + r"baidu" + SE + r"platform"),
        "version_hints": [r"baidu[-/ ]map[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://lbsyun.baidu.com/",
    },
    "Tencent Map": {
        "category": "location",
        "package_pattern": re.compile(r"com" + SE + r"tencent" + SE + r"map|com" + SE + r"tencent" + SE + r"tencentmap"),
        "version_hints": [],
        "homepage": "https://lbs.qq.com/",
    },

    # ---------------- 数据库 ----------------
    "GreenDAO": {
        "category": "database",
        "package_pattern": re.compile(r"org" + SE + r"greenrobot" + SE + r"greendao"),
        "version_hints": [r"greendao[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://greenrobot.org/greendao/",
    },
    "Room (AndroidX)": {
        "category": "database",
        "package_pattern": re.compile(r"androidx" + SE + r"room"),
        "version_hints": [r"room[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://developer.android.com/jetpack/androidx/releases/room",
    },

    # ---------------- 容器 / 工具 ----------------
    "EventBus": {
        "category": "util",
        "package_pattern": re.compile(r"org" + SE + r"greenrobot" + SE + r"eventbus"),
        "version_hints": [r"eventbus[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://greenrobot.org/eventbus/",
    },
    "RxJava": {
        "category": "util",
        "package_pattern": re.compile(r"io" + SE + r"reactivex"),
        "version_hints": [r"rxjava[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://github.com/ReactiveX/RxJava",
    },
    "Lombok": {
        "category": "util",
        "package_pattern": re.compile(r"lombok" + SE),
        "version_hints": [r"lombok[-/ ](\d+\.\d+\.\d+)"],
        "homepage": "https://projectlombok.org/",
    },

    # ---------------- XML 处理（XSLT / SAX / DOM / Pull-parser） ----------------
    "Apache Xalan": {
        "category": "xml",
        # XSLT 处理器（CVE-2022-34169 整数截断 → RCE）
        "package_pattern": re.compile(r"org" + SE + r"apache" + SE + r"xalan"),
        "version_hints": [r"xalan[-/ ](\d+\.\d+\.\d+)"],
        "global_version_patterns": [
            r"Xalan[- ](\d+\.\d+\.\d+)",
            r"xalan[-_](\d+\.\d+\.\d+)",
        ],
        # jadx 兜底：org.apache.xalan.Version 类的 getVersion() 实现里硬编码版本字符串
        # 源码形如：return "Xalan 2.7.2";  或  new String("2.7.2")
        "jadx_version_patterns": [
            # Version.getVersion() 返回字面量
            r'return\s+"Xalan[ ]+(\d+\.\d+\.\d+)"',
            r'return\s+"(\d+\.\d+\.\d+)"',
            # Version 类的静态常量：public static final String VERSION = "2.7.2"
            r'public\s+static\s+final\s+String\s+VERSION\s*=\s*"Xalan[ ]+(\d+\.\d+\.\d+)"',
            r'public\s+static\s+final\s+String\s+VERSION\s*=\s*"(\d+\.\d+\.\d+)"',
            # SAXSource 等关键类开头的 javadoc 注释
            r"@version\s+(\d+\.\d+\.\d+)",
            r"//\s*Xalan-J\s+(\d+\.\d+\.\d+)",
            # Implementation-Version
            r"Implementation-Version:\s*(\d+\.\d+\.\d+)",
        ],
        "jadx_package_dirs": [
            "org/apache/xalan/",           # AOSP / Maven 同名路径
            "org/apache/xml/serializer/",  # Xalan 序列化子模块（含独立 Version.java）
            "com/android/org/apache/xalan/",
        ],
        # AOSP 把 Xalan 版本号拆成三个 int getter（jadx 内联常量后无版本字符串）：
        #   getMajorVersionNum() → 2 / getReleaseVersionNum() → 7 / getMaintenanceVersionNum() → 1
        # 需要专门的 int getter 提取器才能拿到 2.7.1
        "jadx_int_getter": True,
        "homepage": "https://xalan.apache.org/",
    },
    "Apache Xerces": {
        "category": "xml",
        # XML DOM/SAX 解析器
        "package_pattern": re.compile(r"org" + SE + r"apache" + SE + r"xerces"),
        "version_hints": [r"xerces(?:Impl)?[-/ ](\d+\.\d+\.\d+)"],
        # Xerces-J 官方 artifact 名称格式：Xerces-J-bin.X.Y.Z.tar.gz / Xerces-J X.Y.Z
        "global_version_patterns": [
            r"Xerces-J[- ](\d+\.\d+\.\d+)",
            r"xercesImpl[-_](\d+\.\d+\.\d+)",
            r"xerces[-_](\d+\.\d+\.\d+)",
        ],
        # jadx 兜底：org.apache.xerces.impl.Version 类的 fVersion 静态常量赋值
        # 源码形如：static String fVersion = "Xerces 2.12.0"; 或 fXercesVersion = "2.12.0";
        "jadx_version_patterns": [
            r'(?:static\s+)?(?:final\s+)?String\s+f?Version\s*=\s*"Xerces[ ]+(\d+\.\d+\.\d+)"',
            r'(?:static\s+)?(?:final\s+)?String\s+f?Version\s*=\s*"(\d+\.\d+\.\d+)"',
            r'return\s+"Xerces[ ]+(\d+\.\d+\.\d+)"',
            r"//\s*Xerces-J\s+(\d+\.\d+\.\d+)",
            r"@version\s+(\d+\.\d+\.\d+)",
            r"Implementation-Version:\s*(\d+\.\d+\.\d+)",
        ],
        "jadx_package_dirs": [
            "org/apache/xerces/",
            "com/android/org/apache/xerces/",
        ],
        "homepage": "https://xerces.apache.org/",
    },
    "Apache SAX": {
        "category": "xml",
        # org.xml.sax.* —— SAX 事件驱动 XML 解析接口
        "package_pattern": re.compile(r"org" + SE + r"xml" + SE + r"sax"),
        "version_hints": [],
        # SAX 自身无版本（仅 API），但常与 Xerces 绑定
        "global_version_patterns": [
            r"SAX (\d+\.\d+\.\d+)",
            r"sax2[-_](\d+\.\d+\.\d+)",
        ],
        # jadx 兜底：SAX 是 JDK 标准 API（org.xml.sax.*），没有版本概念，
        # 这里只匹配注释中可能出现的 "SAX 2.0.2" 之类的描述。
        "jadx_version_patterns": [
            r"//\s*SAX\s+(\d+\.\d+\.\d+)",
            r"@version\s+(\d+\.\d+\.\d+)",
            r"Implementation-Version:\s*(\d+\.\d+\.\d+)",
        ],
        "jadx_package_dirs": [
            "org/xml/sax/",
        ],
        "homepage": "https://www.saxproject.org/",
    },
    "kxml2": {
        "category": "xml",
        # Android 生态常用的轻量级 XML pull-parser（kSOAP / 旧 Android SDK 内部依赖）
        "package_pattern": re.compile(r"org" + SE + r"kxml2"),
        "version_hints": [r"kxml2[-/ ](\d+\.\d+\.\d+)"],
        "global_version_patterns": [
            r"kxml2[-_](\d+\.\d+\.\d+)",
            r"kxml[- ](\d+\.\d+\.\d+)",
        ],
        # jadx 兜底：kxml2 KXmlParser 类开头的注释含 "kxml 2.3.0"
        "jadx_version_patterns": [
            r"//\s*kxml2[- ](\d+\.\d+\.\d+)",
            r"//\s*kxml\s+(\d+\.\d+\.\d+)",
            r"(?:final\s+)?(?:static\s+)?String\s+(?:VERSION|version)\s*=\s*\"(\d+\.\d+\.\d+)\"",
            r"@version\s+(\d+\.\d+\.\d+)",
            r"Implementation-Version:\s*(\d+\.\d+\.\d+)",
        ],
        "jadx_package_dirs": [
            "com/android/org/kxml2/",
            "org/kxml2/",
        ],
        "homepage": "https://sourceforge.net/projects/kxml/",
    },

    # ---------------- 加固检测（不是 SDK，是产品形态标记） ----------------
    # 检测到 = APK 被对应方案加固，DEX 中业务代码被加密/抽空，
    # 此时静态扫描结果严重低估实际 SDK 暴露面。
    "Bangcle (SecNeo)": {
        "category": "hardener",
        # 梆梆加固壳的标志性类（壳解密前的桩类）：AP/AW/CP/H 四件套
        "package_pattern": re.compile(r"com" + SE + r"secneo" + SE + r"apkwrapper" + SE + r"(?:AP|AW|CP|H)\b"),
        "version_hints": [],   # 加固版本不参与 CVE 比对
        "homepage": "https://www.bangcle.com/",
    },
}

# ----------------------------------------------------------------------
# 高危类别专项（加密 / 网络 / WebView / 序列化）
# ----------------------------------------------------------------------

HIGH_RISK_CATEGORIES: dict[str, dict] = {
    "crypto": {
        "title": "加密库（OpenSSL / BouncyCastle）",
        "description": "加密库历史 CVE 频发，常因弱算法、降级攻击、TLS 协议实现缺陷导致中间人攻击",
        "severity": "CRITICAL",
        "so_signals": ["libcrypto.so", "libssl.so", "libconscrypt.so", "libbcprov.so"],
        "historical_cves": [
            {"id": "CVE-2016-2107", "cvss": 7.5, "desc": "OpenSSL Padding Oracle 攻击"},
            {"id": "CVE-2016-0701", "cvss": 5.0, "desc": "OpenSSL DH 弱密钥 (Logjam)"},
            {"id": "CVE-2014-0224", "cvss": 6.8, "desc": "OpenSSL TLS Renegotiation CCS Injection"},
            {"id": "CVE-2022-0778", "cvss": 7.5, "desc": "OpenSSL 无限循环导致 DoS"},
            {"id": "CVE-2023-0286", "cvss": 7.4, "desc": "OpenSSL X.400 类型混淆"},
        ],
        "recommendation": "升级到 OpenSSL 1.1.1u+ / 3.0.9+ / BouncyCastle 1.78+；禁用 SSLv3/TLS1.0/1.1；启用 CertificatePinner",
    },
    "network": {
        "title": "网络库（OkHttp / Retrofit / HttpClient）",
        "description": "网络库历史 CVE 涉及证书校验绕过、明文流量、连接泄漏",
        "severity": "HIGH",
        "so_signals": ["libcurl.so", "libokhttp.so"],
        "historical_cves": [
            {"id": "CVE-2021-0341", "cvss": 7.5, "desc": "OkHttp 主机名校验绕过"},
            {"id": "CVE-2023-3635", "cvss": 7.5, "desc": "OkHttp 5.x GzipSource 整数溢出"},
            {"id": "CVE-2018-1000850", "cvss": 9.8, "desc": "Retrofit 反序列化 RCE（搭配 Gson）"},
        ],
        "recommendation": "OkHttp 升级到 4.12+ / 5.0.0-alpha.14+；Retrofit 2.9.0+；强制 HTTPS + CertificatePinner",
    },
    "webview": {
        "title": "WebView 组件",
        "description": "WebView 历史 CVE 涉及 JS 桥接任意命令执行、File 域同源策略绕过",
        "severity": "HIGH",
        "so_signals": [],
        "historical_cves": [
            {"id": "CVE-2019-3004", "cvss": 9.8, "desc": "WebView addJavascriptInterface RCE（API<17）"},
            {"id": "CVE-2020-0103", "cvss": 7.8, "desc": "WebView SameSite Cookie 绕过"},
            {"id": "CVE-2020-6502", "cvss": 8.8, "desc": "WebView URL 欺骗"},
        ],
        "recommendation": "禁用 addJavascriptInterface；启用 WebView.setSafeBrowsingEnabled(true)；File 域访问关闭；强制 https only",
    },
    "serialize": {
        "title": "序列化库（Fastjson / Gson / Jackson）",
        "description": "Fastjson 历史多次爆 RCE；Jackson 默认配置可触发反序列化漏洞",
        "severity": "CRITICAL",
        "so_signals": [],
        "historical_cves": [
            {"id": "CVE-2017-18349", "cvss": 9.8, "desc": "Fastjson 1.2.24 反序列化 RCE"},
            {"id": "CVE-2019-14439", "cvss": 9.8, "desc": "Fastjson 1.2.48 之前反序列化 RCE"},
            {"id": "CVE-2022-25845", "cvss": 9.8, "desc": "Fastjson 1.2.83 之前反序列化 RCE"},
            {"id": "CVE-2019-12384", "cvss": 9.8, "desc": "Jackson RCE (enableDefaultTyping)"},
        ],
        "recommendation": "Fastjson 升级到 1.2.83+ 并启用 safeMode；Jackson 关闭 enableDefaultTyping；或迁移到 Gson/Moshi",
    },
    "xml": {
        "title": "XML 处理（Apache Xalan / Xerces / SAX / kxml2）",
        "description": "Xalan XSLT 处理器存在整数截断 RCE（CVE-2022-34169）；Xerces 历史 XML 解析 XXE；SAX 默认实现不安全",
        "severity": "CRITICAL",
        "so_signals": [],
        "historical_cves": [
            {"id": "CVE-2022-34169", "cvss": 9.8, "desc": "Apache Xalan XSLT 整数截断 → RCE"},
            {"id": "CVE-2022-23437", "cvss": 9.8, "desc": "Apache Xerces XInclude 处理 RCE"},
            {"id": "CVE-2013-4002", "cvss": 7.5, "desc": "Xerces XML 解析 DoS（十亿笑攻击）"},
        ],
        "recommendation": "Xalan 升级到 2.7.12+；Xerces 升级到 2.12.2+；禁用外部实体（XXE）解析；限制 XSLT 处理不可信 XML",
    },
}

# ----------------------------------------------------------------------
# 版本号提取
# ----------------------------------------------------------------------

VERSION_REGEX = re.compile(
    r"(?:v|version|ver)?\s*"
    r"(\d{1,3}\.\d{1,3}(?:\.\d{1,5})?(?:[-+][a-zA-Z0-9]+)?)",
    re.IGNORECASE,
)

def extract_version(context: str, hints: list[str]) -> str | None:
    """从上下文中提取版本号。

    只用 SDK 特有的 hints 正则，命中即返回；未命中返回 None。

    【v9 重要修正】这里曾经有一层"通用 VERSION_REGEX 兜底"：hints 没命中时，
    在匹配点 ±600 字符窗口里抓任意形如 x.y.z 的数字。实测证明这是误报主因——
    在真实 App 上产出过 OkHttp@537.36（Chrome User-Agent 里的 Chrome 版本）、
    OkHttp@165.942、Gson@26.1（Android API 级别）这类完全无关的"版本号"，
    并据此报出 20 条虚假 CVE。

    根因：某个数字出现在 okhttp 引用附近的 600 字符内，不代表它是 okhttp 的版本。
    这种"就近抓取"在源码/DEX 这种高噪声文本里不可用。宁可报"版本未知"，
    也不要报一个会让用户去排查不存在的漏洞的错误版本。
    """
    for hint in hints:
        m = re.search(hint, context, re.IGNORECASE)
        if m:
            return m.group(1)
    return None

def extract_version_global(
    text: str,
    patterns: list[str],
    validators: list | None = None,
) -> str | None:
    """在整个目标文本（DEX 字符串集 / jadx 全源码）中提取版本号。

    与 extract_version 不同的是：没有上下文窗口限制，而是在整个文本中查找。
    用于提取 SDK 特有的全局版本标记（如 okhttp/4.9.0 User-Agent、Xerces-J 2.12.0 等）。

    策略：
    1. 对每个 pattern 在全文本扫描所有候选，返回首个通过所有验证器的
    2. 按 pattern 列表顺序优先级递减
    3. validators 是可选的验证函数列表，对候选版本号做合法性检查
       （如过滤掉 IP 地址、OID 等误报）

    注意：必须用 re.finditer 而非 re.search，否则只能拿到第一个候选（可能是 IP）。
    """
    if validators is None:
        validators = []

    for pat in patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            try:
                v = m.group(1)
            except (IndexError, AttributeError):
                v = m.group(0)
            if v and all(fn(v) for fn in validators):
                return v
    return None

# 常用验证器
def is_chromium_version(v: str) -> bool:
    """判断字符串是否像合法的 Chromium 4 段版本号

    Chromium 浏览器版本号规则：
    - 第 1 段 ∈ [50, 130]（排除远古版与未来版；IP 第一段可达 223，需 <= 130 过滤）
    - 第 3 段 >= 4000（排除大多数私有 IP / OID）

    返回 True 表示可能是合法的 Chromium 版本号。
    """
    parts = v.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = list(map(int, parts))
    except ValueError:
        return False
    return 50 <= nums[0] <= 130 and 0 <= nums[1] < 10000 and 4000 <= nums[2] < 10000 and 0 <= nums[3] < 1000

def is_not_ip(v: str) -> bool:
    """判断字符串是否不是 IPv4 地址"""
    parts = v.split(".")
    if len(parts) != 4:
        return True
    try:
        nums = list(map(int, parts))
    except ValueError:
        return True
    # IP 第 1 段通常 <= 223（排除多播 224+/未来），第 4 段 != 0 时通常是真实端点
    if 0 <= nums[0] <= 223 and 0 <= nums[1] <= 255 and 0 <= nums[2] <= 255 and 0 <= nums[3] <= 255:
        return False
    return True

# 路径片段停用词：这些是厂商/组织名，不能作为 SDK 锚点关键词
_PATH_STOPWORDS = frozenset({
    "com", "android", "org", "net", "io", "java", "javax", "sun", "jdk",
    "google", "squareup", "apache", "github", "internal", "thirdparty",
    "libs", "lib", "app", "src", "main", "core",
})

def _sdk_keywords(package_dirs: list[str]) -> set[str]:
    """从 package_dirs 提取可用于判断"是否自带 SDK 名锚点"的关键词。

    例：["com/android/okhttp/", "okhttp3/"] → {"okhttp", "okhttp3"}
    停用词（com/android/org 等厂商名）会被剔除，否则几乎所有模式都会被
    误判为"已锚定"。
    """
    keywords: set[str] = set()
    for d in package_dirs:
        for seg in re.split(r"[/\\.]", d):
            seg = seg.strip().lower()
            if len(seg) >= 3 and seg not in _PATH_STOPWORDS:
                keywords.add(seg)
    return keywords

def _pattern_is_anchored(pattern: str, keywords: set[str]) -> bool:
    """判断正则是否自带 SDK 名锚点（可安全用于全库扫描）。

    带锚点：`//\\s*(?:OkHttp|okhttp)\\s+version\\s+(...)`  —— 含 "okhttp"
    无锚点：`public static final String VERSION = "..."`  —— 任何库都长这样

    无锚点的模式只能在 SDK 自己的包目录里用，否则会命中全库第一个无关文件。
    """
    if not keywords:
        return False
    tokens = set(re.findall(r"[A-Za-z]{3,}", pattern))
    return any(t.lower() in keywords for t in tokens)

def _collect_java_files(jadx_dir: Path) -> list[tuple[str, str]]:
    """收集 jadx 输出目录下的所有 .java 文件，返回 [(相对路径, 内容), ...]"""
    sources_candidates = [jadx_dir]
    sources_sub = jadx_dir / "sources"
    if sources_sub.exists():
        sources_candidates.insert(0, sources_sub)

    files: list[tuple[str, str]] = []
    seen: set[Path] = set()
    for src_root in sources_candidates:
        if not src_root.is_dir():
            continue
        for java_file in src_root.rglob("*.java"):
            if java_file in seen:
                continue
            seen.add(java_file)
            try:
                rel = str(java_file.relative_to(src_root)).replace("\\", "/")
                files.append((rel, java_file.read_text(errors="ignore")))
            except Exception:
                continue
    return files

def extract_version_from_jadx(
    jadx_dir: Path | str | None,
    sdk_name: str,
    patterns: list[str],
    validators: list | None = None,
    package_dirs: list[str] | None = None,
) -> str | None:
    """从 jadx 反编译输出的 .java 源码中提取 SDK 版本号。

    两阶段搜索（v9 修复）：
      阶段 1（包内搜索）：只在 package_dirs 命中的源码目录里搜，用全部模式。
                —— 这是主路径，能安全使用 `VERSION = "x.y.z"` 这类通用模式。
      阶段 2（全库搜索）：仅在包内未命中时进行，且**只使用自带 SDK 名锚点的
                模式**（如含 "okhttp"/"Xalan" 的正则），避免误命中无关文件。

    参数：
      jadx_dir: jadx 反编译输出根目录（含 sources/ 子目录）
      sdk_name: SDK 显示名（日志用）
      patterns: 版本号正则列表（与 global_version_patterns 写法一致）
      validators: 验证函数列表
      package_dirs: SDK 源码所在目录片段，如 ["com/android/okhttp/"]。
                    强烈建议提供——不提供时只能走阶段 2 的锚点模式，覆盖率会下降。

    返回：版本号字符串；未命中返回 None
    """
    if not patterns:
        return None
    if validators is None:
        validators = []
    if jadx_dir is None:
        return None

    jadx_path = Path(jadx_dir)
    if not jadx_path.exists():
        return None

    files = _collect_java_files(jadx_path)
    if not files:
        return None

    package_dirs = package_dirs or []

    # 阶段 1：包内搜索（全模式，安全）
    if package_dirs:
        scoped_text = "\n".join(
            content for rel, content in files
            if any(d in rel for d in package_dirs)
        )
        if scoped_text:
            ver = extract_version_global(scoped_text, patterns, validators)
            if ver:
                return ver

    # 阶段 2：全库搜索（仅锚点模式）
    keywords = _sdk_keywords(package_dirs)
    anchored = [p for p in patterns if _pattern_is_anchored(p, keywords)]
    if not anchored:
        return None
    combined = "\n".join(content for _, content in files)
    return extract_version_global(combined, anchored, validators)

# ----------------------------------------------------------------------
# int getter 版本提取（AOSP Xalan 这类把版本拆成 int 常量的写法）
# ----------------------------------------------------------------------

_INT_GETTER_PATTERNS = {
    "major": r"getMajorVersionNum\s*\(\s*\)\s*\{\s*return\s+(\d+)\s*;",
    "minor": r"getReleaseVersionNum\s*\(\s*\)\s*\{\s*return\s+(\d+)\s*;",
    "patch": r"getMaintenanceVersionNum\s*\(\s*\)\s*\{\s*return\s+(\d+)\s*;",
}

def extract_version_from_int_getters(java_text: str) -> str | None:
    """从 Version.java 源码中提取被拆成 int getter 的版本号。

    适配 AOSP Xalan / Xalan-Serializer：jadx 把版本号常量内联后，源码里
    没有 "2.7.1" 这样的字符串，只有三个返回 int 的方法：

        public static int getMajorVersionNum()      { return 2; }
        public static int getReleaseVersionNum()    { return 7; }
        public static int getMaintenanceVersionNum(){ return 1; }

    返回 "2.7.1"；三个方法缺任一个则返回 None。
    """
    got = {}
    for key, pat in _INT_GETTER_PATTERNS.items():
        m = re.search(pat, java_text)
        if not m:
            return None
        got[key] = m.group(1)
    return f"{got['major']}.{got['minor']}.{got['patch']}"

def extract_version_int_getters_from_dir(
    jadx_dir: Path | str | None,
    package_dirs: list[str] | None = None,
) -> tuple[str | None, str | None]:
    """在 jadx 输出目录里找 Version.java 并用 int getter 提取版本号。

    返回 (版本号, 来源文件相对路径)；未命中返回 (None, None)。
    """
    if jadx_dir is None:
        return None, None
    jadx_path = Path(jadx_dir)
    if not jadx_path.exists():
        return None, None

    package_dirs = package_dirs or []
    for rel, content in _collect_java_files(jadx_path):
        # 只看 Version.java（AOSP/Apache 的惯例命名）
        if not rel.endswith("/Version.java") and rel != "Version.java":
            continue
        if package_dirs and not any(d in rel for d in package_dirs):
            continue
        ver = extract_version_from_int_getters(content)
        if ver:
            return ver, rel
    return None, None

# ==============================================================================
# 模块：lib/cve_checker.py
# ==============================================================================

try:
    import requests
except ImportError:
    requests = None

# NVD 2.0 API 端点
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 速率限制（NVD 官方：无 key = 5 次/30s，有 key = 50 次/30s）
RATE_LIMIT_DELAY_NO_KEY = 6.0
RATE_LIMIT_DELAY_WITH_KEY = 0.6

# ----------------------------------------------------------------------
# 内置离线 CVE 表（关键高危组件历史 CVE，兜底用）
# ----------------------------------------------------------------------

BUILTIN_CVE_TABLE: dict[str, list[dict[str, Any]]] = {
    # 用 component_name（含版本范围或关键词）做 key
    "okhttp": [
        {"id": "CVE-2021-0341", "cvss_v3": 7.5, "desc": "OkHttp hostnameVerifier bypass", "affected": "<4.9.0"},
        {"id": "CVE-2023-3635", "cvss_v3": 7.5, "desc": "OkHttp GzipSource integer overflow", "affected": "<4.12.0"},
    ],
    "retrofit": [
        {"id": "CVE-2018-1000850", "cvss_v3": 9.8, "desc": "Retrofit + Gson deserialization RCE", "affected": "<2.6.0"},
    ],
    "fastjson": [
        # 1.1.x 系列（阿里 fork 分支，与 1.2.x 主线 CVE 不互通）
        # 1.2.* 与 <1.1.46.sec01 用 AND：分支锁定 + 上限
        {"id": "CVE-2017-18349", "cvss_v3": 9.8, "desc": "Fastjson 1.1.x 系列 parseObject RCE（修复版本 1.1.46.sec01）", "affected": "1.1.*,<1.1.46.sec01"},
        # 1.2.x 系列（官方主线）
        {"id": "CVE-2017-18349", "cvss_v3": 9.8, "desc": "Fastjson 1.2.x 系列 parseObject RCE（修复版本 1.2.25）", "affected": "1.2.*,<1.2.25"},
        {"id": "CVE-2019-14439", "cvss_v3": 9.8, "desc": "Fastjson deserialization RCE (TemplatesImpl)", "affected": "1.2.*,<1.2.51"},
        {"id": "CVE-2022-25845", "cvss_v3": 9.8, "desc": "Fastjson autoType RCE", "affected": "1.2.*,<1.2.83"},
    ],
    "gson": [
        {"id": "CVE-2022-25647", "cvss_v3": 9.8, "desc": "Gson deserialization of untrusted data", "affected": "<2.8.9"},
    ],
    "jackson": [
        {"id": "CVE-2019-12384", "cvss_v3": 9.8, "desc": "Jackson deserialization RCE via enableDefaultTyping", "affected": "<2.9.10"},
        {"id": "CVE-2019-14439", "cvss_v3": 9.8, "desc": "Jackson polymorphic deserialization", "affected": "<2.9.10"},
    ],
    "openssl": [
        {"id": "CVE-2016-2107", "cvss_v3": 7.5, "desc": "OpenSSL AES-NI padding oracle", "affected": "<1.0.1t|<1.0.2h"},
        {"id": "CVE-2016-0701", "cvss_v3": 5.0, "desc": "OpenSSL DH small subgroup (Logjam)", "affected": "<1.0.1f|<1.0.2"},
        {"id": "CVE-2022-0778", "cvss_v3": 7.5, "desc": "OpenSSL infinite loop DoS", "affected": "<1.1.1n|<3.0.2"},
        {"id": "CVE-2023-0286", "cvss_v3": 7.4, "desc": "OpenSSL X.400 type confusion", "affected": "<1.0.2zu|<1.1.1x|<3.0.8"},
    ],
    "bouncycastle": [
        {"id": "CVE-2022-0778", "cvss_v3": 7.5, "desc": "BC SSL infinite loop", "affected": "<1.70"},
        {"id": "CVE-2023-33202", "cvss_v3": 9.8, "desc": "BouncyCastle LDAP injection", "affected": "<1.78"},
    ],
    "webview": [
        {"id": "CVE-2019-3004", "cvss_v3": 9.8, "desc": "WebView addJavascriptInterface RCE", "affected": "<Android 5.0"},
    ],
}

def _component_key(component: str) -> str:
    """从 'OkHttp@4.9.0' 或 'com.squareup.okhttp3:okhttp:4.9.0' 提取可查询的 key"""
    # 去掉 @version
    base = component.split("@")[0]
    # 取最后一段
    name = base.split(":")[-1].lower()
    # 去除常见前缀
    for prefix in ("lib", "android-", "android_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name

def _version_tuple(v: str) -> tuple:
    """把版本字符串解析为 (major, minor, patch, suffix) 元组，方便比较。

    例：
      "1.2.25"         → (1, 2, 25, "")
      "1.1.46.sec01"   → (1, 1, 46, "sec01")
      "1.2.83-RC1"     → (1, 2, 83, "rc1")
      "4.12.0"         → (4, 12, 0, "")
    不识别的格式按空元组返回，比较时会落到最小值。
    """
    import re
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[.\-+]?(.+))?", v.strip())
    if not m:
        return ()
    a, b, c, suf = m.groups()
    # suffix 标准化：小写、去掉点
    suf = (suf or "").lower().replace(".", "")
    return (int(a), int(b), int(c or 0), suf)

def _is_version_affected(version: str, affected: str) -> bool:
    """判断 version 是否在 affected 字符串描述的影响范围内。

    affected 语义：
      - 当含 | 时表示 OR（任一子条件成立即命中）—— 适用"<1.2.25|<3.0.0"
      - 当含 , 时表示 AND（所有子条件同时成立才命中）—— 适用"1.2.*,<1.2.25"

    每个子条件支持的运算符：
      - "<X.Y.Z"  单边上限（<）
      - ">=X.Y.Z" 单边下限（>=）
      - ">X.Y.Z" / "<=X.Y.Z" / ">=X.Y.Z" / "<X.Y.Z"
      - "X.Y.Z"   精确等于
      - "X.Y.*"   前缀通配（major.minor 锁定，避免跨分支误命中）

    返回 True 表示 version 在受影响范围内。

    说明：Fastjson 1.1.x vs 1.2.x 是不同分支，需要 AND 锁定；其它情况
    的多版本范围用 OR 表达更直观。
    """
    if not version or not affected:
        return False
    ver_t = _version_tuple(version)
    if not ver_t:
        return False

    # AND（逗号）优先级高于 OR（竖线）
    or_parts = affected.split("|")
    for or_part in or_parts:
        and_parts = or_part.split(",")
        all_match = True
        for part in and_parts:
            part = part.strip()
            if not part:
                continue
            if not _match_single_condition(ver_t, part):
                all_match = False
                break
        if all_match:
            return True
    return False

def _match_single_condition(ver_t: tuple, part: str) -> bool:
    """判断 ver_t 是否满足单个条件（带运算符）。支持 X.Y.* 前缀通配。"""
    if part.startswith("<="):
        op = "<="; ref = part[2:].strip()
    elif part.startswith(">="):
        op = ">="; ref = part[2:].strip()
    elif part.startswith("<"):
        op = "<";  ref = part[1:].strip()
    elif part.startswith(">"):
        op = ">";  ref = part[1:].strip()
    elif part.startswith("="):
        op = "=";  ref = part[1:].strip()
    else:
        op = "=";  ref = part

    # 前缀通配 X.Y.*：锁定到特定 major.minor 分支
    if ref.endswith(".*") or ref.endswith(".x"):
        ref_prefix = ref.rstrip(".*x").rstrip(".")
        try:
            pmaj, pmin, *_ = [int(x) for x in ref_prefix.split(".")]
            return ver_t[0] == pmaj and ver_t[1] == pmin
        except (ValueError, IndexError):
            return False

    ref_t = _version_tuple(ref)
    if not ref_t:
        return False
    try:
        if op == "<"  and ver_t < ref_t:  return True
        if op == "<=" and ver_t <= ref_t: return True
        if op == ">"  and ver_t > ref_t:  return True
        if op == ">=" and ver_t >= ref_t: return True
        if op == "="  and ver_t == ref_t: return True
    except TypeError:
        return False
    return False

class CVEChecker:
    """NVD CVE 查询器（在线 + 离线双模式）"""

    def __init__(self, api_key: str | None = None, cache_dir: Path | None = None):
        self.api_key = api_key
        self.cache_dir = cache_dir
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)
        self._last_request_time = 0.0
        self._online = requests is not None

    # ---------- 缓存 ----------

    def _cache_path(self, query: str) -> Path:
        h = hashlib.md5(query.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{h}.json"

    def _load_cache(self, query: str) -> dict | None:
        if not self.cache_dir:
            return None
        p = self._cache_path(query)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def _save_cache(self, query: str, data: dict) -> None:
        if not self.cache_dir:
            return
        try:
            self._cache_path(query).write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
        except Exception:
            pass

    # ---------- 速率限制 ----------

    def _throttle(self) -> None:
        delay = RATE_LIMIT_DELAY_WITH_KEY if self.api_key else RATE_LIMIT_DELAY_NO_KEY
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    # ---------- 在线查询 ----------

    def _query_nvd(self, keyword: str) -> list[dict[str, Any]]:
        """调用 NVD 2.0 API"""
        if not self._online:
            return []

        query = f"keyword:{keyword}"
        cached = self._load_cache(query)
        if cached is not None:
            return cached.get("cves", [])

        self._throttle()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            # 网络错误：返回空（后续会走离线表）
            return []

        cves: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            # 描述取英文优先
            descs = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descs if d.get("lang") == "en"),
                descs[0]["value"] if descs else "",
            )
            # CVSS v3 score
            cvss = None
            for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
                cvss = metric.get("cvssData", {}).get("baseScore")
                break
            if cvss is None:
                for metric in cve.get("metrics", {}).get("cvssMetricV30", []):
                    cvss = metric.get("cvssData", {}).get("baseScore")
                    break
            cves.append({
                "id": cve_id,
                "cvss_v3": cvss,
                "desc": desc_en[:300],
                "published": cve.get("published", ""),
            })

        self._save_cache(query, {"cves": cves})
        return cves

    # ---------- 离线兜底 ----------

    def _lookup_offline(self, component: str) -> list[dict[str, Any]]:
        """从内置表查（无网络时兜底）"""
        key = _component_key(component)
        # 提取版本号（如 'Fastjson@1.1.46' → '1.1.46'）
        version = ""
        if "@" in component:
            version = component.split("@", 1)[1].strip()

        results = []
        for table_key, cves in BUILTIN_CVE_TABLE.items():
            if table_key in key or key in table_key:
                for cve in cves:
                    affected = cve.get("affected", "")
                    if affected and version:
                        # 分支锁定：affected 中的 X.Y.* 表示仅影响该 major.minor 分支，
                        # 与其它分支（如 Fastjson 1.1.x vs 1.2.x）必须隔离判断。
                        # 如果 affected 没有 X.Y.* 前缀，则用 _is_version_affected 做纯版本范围匹配。
                        expected_branch = None
                        for part in affected.split("|"):
                            p = part.strip()
                            if p.endswith(".*"):
                                expected_branch = p.rstrip(".*").strip()
                                break
                        if expected_branch:
                            ver_branch = ".".join(version.split(".")[:2])
                            if ver_branch != expected_branch:
                                continue  # 分支不匹配（跨分支误命中）
                        if not _is_version_affected(version, affected):
                            continue
                    results.append(cve)
        # 按 CVE id 去重：保留最精确描述（desc 最长的那条）。
        # 同 CVE 在 1.1.x/1.2.x 双分支时会出现两条，去重避免报告噪音。
        seen: dict[str, dict] = {}
        for cve in results:
            cid = cve.get("id")
            if not cid:
                continue
            if cid not in seen or len(cve.get("desc", "")) > len(seen[cid].get("desc", "")):
                seen[cid] = cve
        return list(seen.values())

    # ---------- 公开接口 ----------

    def lookup(self, component: str) -> list[dict[str, Any]]:
        """查询组件 CVE。先尝试在线，无结果时回退离线表。

        component 格式：
          - 'OkHttp@4.9.0'（带版本）
          - 'com.squareup.okhttp3:okhttp:4.9.0'（Maven 坐标）
        """
        key = _component_key(component)

        # 1. 在线查询
        cves = self._query_nvd(key)

        # 2. 在线失败 → 离线表
        if not cves:
            cves = self._lookup_offline(component)

        # 3. 简化结果（只保留必要字段）
        return [
            {
                "id": c["id"],
                "cvss_v3": c.get("cvss_v3"),
                "desc": c.get("desc", ""),
                "source": "NVD" if c.get("published") else "BUILTIN",
            }
            for c in cves
        ]

# ==============================================================================
# 模块：lib/version_fingerprint.py
# ==============================================================================

# ----------------------------------------------------------------------
# ① 版本常量提取（高精度，优先于一切指纹）
# ----------------------------------------------------------------------

# 覆盖 Jackson 系 PackageVersion、以及 Version 构造器传字符串的写法。
# 例：com/fasterxml/jackson/core/json/PackageVersion.java 中
#     VERSION = VersionUtil.parseVersion("2.8.7", "com.fasterxml.jackson.core", "jackson-core")
VERSION_CONSTANT_PATTERNS: list[tuple[str, str]] = [
    ("parseVersion", r'parseVersion\(\s*"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)"'),
    ("Version-ctor", r'new\s+Version\s*\(\s*"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)"'),
    ("version-string", r'(?:PACKAGE_)?VERSION_STRING\s*=\s*"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)"'),
]

# 这些文件名天然是「版本载体」，命中时可信度最高
VERSION_CARRIER_NAMES = ("PackageVersion", "Version", "BuildConfig", "BuildInfo")

def extract_version_constants_from_dir(
    jadx_dir: Path, package_dirs: list[str]
) -> tuple[str | None, str | None]:
    """在指定包目录下搜索版本常量。

    返回 ``(version, source_file)``。优先采信 PackageVersion/Version 这类
    版本载体文件，避免在 SDK 业务代码里误命中同名常量。
    """
    root = Path(jadx_dir)
    if not root.exists():
        return None, None
    # 作用域是硬性要求。没有包目录限定就退化成全库扫描，
    # 会把某个库的版本常量（如 Jackson 的 2.8.7）误配给每一个没配作用域的 SDK。
    if not package_dirs:
        return None, None

    fallback: tuple[str | None, str | None] = (None, None)
    for f in sorted(root.rglob("*.java")):
        rel = str(f)
        if not any(d in rel for d in package_dirs):
            continue
        try:
            text = f.read_text(errors="ignore")
        except Exception:
            continue
        is_carrier = any(n in f.name for n in VERSION_CARRIER_NAMES)
        for kind, pat in VERSION_CONSTANT_PATTERNS:
            m = re.search(pat, text)
            if not m:
                continue
            ver = m.group(1)
            if f.name.startswith("PackageVersion"):
                return ver, rel  # 最强证据，直接返回
            if is_carrier and fallback[0] is None:
                fallback = (ver, rel)
            elif fallback[0] is None:
                fallback = (ver, rel)
    return fallback

# ----------------------------------------------------------------------
# ② 类 / 方法级指纹表
# ----------------------------------------------------------------------
#
# 字段说明：
#   kind      : "class"（类是否存在）| "method"（宿主类内某方法是否存在）
#   path      : kind=class 时的类路径，如 "retrofit2/SkipCallbackExecutorImpl"
#   file      : kind=method 时的源码相对路径，如 "com/google/gson/JsonParser.java"
#   pattern   : kind=method 时用于在宿主文件里搜索的正则
#   since     : 该特征被**引入**的版本（存在 → >= since；缺失 → < since）
#   until     : 该特征被**移除**的版本（存在 → < until）
#   evidence  : 版本结论的来源（changelog 条目 / tag 比对），必填
#   reliable  : 该条作为「上界」证据是否可靠（方法缺失 True；类缺失 False）

FINGERPRINTS: dict[str, list[dict]] = {
    # ------------------------------------------------------------
    # Gson —— changelog 来源：https://google.github.io/gson/CHANGELOG.html
    # ------------------------------------------------------------
    "Gson": [
        {"kind": "class", "path": "com/google/gson/internal/LinkedTreeMap",
         "since": "2.0", "reliable": False,
         "evidence": "Gson 2.0 起存在 internal.LinkedTreeMap"},
        {"kind": "method", "file": "com/google/gson/JsonElement.java",
         "pattern": r"deepCopy\s*\(", "since": "2.8.2", "reliable": True,
         "evidence": "changelog 2.8.2: Introduced a new API, JsonElement.deepCopy()"},
        {"kind": "method", "file": "com/google/gson/GsonBuilder.java",
         "pattern": r"newBuilder\s*\(\s*\)", "since": "2.8.3", "reliable": True,
         "evidence": "changelog 2.8.3: Added a new API, GsonBuilder.newBuilder()"},
        {"kind": "method", "file": "com/google/gson/FieldNamingPolicy.java",
         "pattern": r"LOWER_CASE_WITH_DOTS", "since": "2.8.4", "reliable": True,
         "evidence": "changelog 2.8.4: Added a new FieldNamingPolicy, LOWER_CASE_WITH_DOTS"},
        {"kind": "class", "path": "com/google/gson/internal/JavaVersion",
         "since": "2.8.5", "reliable": False,
         "evidence": "changelog 2.8.5: Moved utils.VersionUtils class to internal.JavaVersion"},
        {"kind": "method", "file": "com/google/gson/JsonParser.java",
         "pattern": r"static\s+JsonElement\s+parseString", "since": "2.8.6", "reliable": True,
         "evidence": "changelog 2.8.6: Added static methods JsonParser.parseString/parseReader"},
        {"kind": "method", "file": "com/google/gson/GsonBuilder.java",
         "pattern": r"disableJdkUnsafe", "since": "2.9.0", "reliable": True,
         "evidence": "changelog 2.9.0: Add GsonBuilder.disableJdkUnsafe()"},
        {"kind": "class", "path": "com/google/gson/internal/ReflectionAccessFilterHelper",
         "since": "2.9.1", "reliable": False,
         "evidence": "changelog 2.9.1: Add support for reflection access filter (#1905)"},
    ],
    # ------------------------------------------------------------
    # Retrofit —— changelog 来源：https://github.com/square/retrofit/blob/master/CHANGELOG.md
    # 注意：OptionalConverterFactory / CompletableFutureCallAdapterFactory 是
    #       2.5.0 内置（原本属于 converter-java8 / adapter-java8 依赖），不是更晚版本。
    # ------------------------------------------------------------
    "Retrofit": [
        {"kind": "class", "path": "retrofit2/HttpServiceMethod",
         "since": "2.5.0", "reliable": False,
         "evidence": "2.5.0 引入 HttpServiceMethod（ServiceMethod 转为抽象基类）"},
        {"kind": "class", "path": "retrofit2/Invocation",
         "since": "2.5.0", "reliable": False,
         "evidence": "changelog 2.5.0: Invocation class provides a reference to the invoked method"},
        {"kind": "class", "path": "retrofit2/internal/EverythingIsNonNull",
         "since": "2.6.0", "reliable": False,
         "evidence": "tag 比对：retrofit2.internal 包自 2.6.0 起出现"},
        {"kind": "class", "path": "retrofit2/SkipCallbackExecutorImpl",
         "since": "2.6.0", "reliable": False,
         "evidence": "changelog 2.6.0: New @SkipCallbackExecutor method annotation"},
        {"kind": "class", "path": "retrofit2/KotlinExtensions",
         "since": "2.6.0", "reliable": False,
         "evidence": "changelog 2.6.0: Support suspend modifier on functions for Kotlin"},
        {"kind": "class", "path": "retrofit2/ServiceMethod",
         "until": "2.7.0", "reliable": True,
         "evidence": "raw.githubusercontent tag 2.7.0 下 retrofit2/ServiceMethod.java 返回 404（已移除）"},
    ],
    # ------------------------------------------------------------
    # Jackson —— 源码里自带 PackageVersion 常量，通常无需走到指纹；
    # 保留几条兜底，用于 PackageVersion 被剔除的场景。
    # ------------------------------------------------------------
    "Jackson": [
        {"kind": "method", "file": "com/fasterxml/jackson/core/util/VersionUtil.java",
         "pattern": r"parseVersion\s*\(", "since": "2.0", "reliable": True,
         "evidence": "VersionUtil.parseVersion 是 jackson-core 2.x 通用入口"},
        {"kind": "class", "path": "com/fasterxml/jackson/core/sym/Name1",
         "since": "2.8", "reliable": False,
         "evidence": "sym/Name1..NameN 细粒度符号缓存，2.8 前后引入"},
        {"kind": "method", "file": "com/fasterxml/jackson/core/JsonParser.java",
         "pattern": r"currentTokenId|getNonBlockingInputFeeder", "since": "2.8", "reliable": True,
         "evidence": "2.8 起 JsonParser 补充 tokenId / non-blocking 相关 API"},
    ],
}

# ----------------------------------------------------------------------
# ③ 版本比较与推断引擎
# ----------------------------------------------------------------------

@dataclass
class VersionEstimate:
    sdk: str
    version: str | None = None          # 收敛到单点时的版本
    lower: str | None = None            # 下界（含）
    upper: str | None = None            # 上界（不含）
    confidence: str = "low"             # high / medium / low
    estimated: bool = True              # 恒为 True：本模块产出永远是估计值
    hits: list[dict] = field(default_factory=list)

    @property
    def range_text(self) -> str:
        if self.version:
            return self.version
        lo = f">= {self.lower}" if self.lower else "?"
        up = f"< {self.upper}" if self.upper else "?"
        if self.lower and self.upper:
            return f"{lo}, {up}"
        return lo if self.lower else up

def _vtuple(v: str) -> tuple:
    """把 '2.8.2' 变成可比较的元组；非数字后缀（如 -rc1）忽略。"""
    parts = re.split(r"[.\-+]", v)
    out = []
    for p in parts:
        if p.isdigit():
            out.append(int(p))
        else:
            break
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])

def _is_patch_successor(lower: str, upper: str) -> bool:
    """判断 upper 是否为 lower 的 **补丁级** 紧邻后继（如 2.8.2 → 2.8.3）。

    只有补丁级相邻才能保证开区间 [lower, upper) 内除了 lower 之外
    **没有其他发布版本**，从而安全收敛到单点。

    反例：lower=2.6.0、upper=2.7.0 属于次版本级相邻，
    区间里可能还夹着 2.6.1/2.6.2/2.6.3/2.6.4（Retrofit 确有这四个版本），
    此时绝不能断言版本就是 2.6.0。
    """
    ma, mi, pa = _vtuple(lower)
    return _vtuple(upper) == (ma, mi, pa + 1)

def extract_class_list(dex_text: str) -> set[str]:
    """从 DEX 字符串里提取类路径集合（形如 com/google/gson/Gson）。"""
    out: set[str] = set()
    for m in re.finditer(r"L([a-zA-Z0-9_$/]{4,}?);", dex_text):
        out.add(m.group(1))
    return out

def estimate_version(
    sdk_name: str,
    class_list: set[str],
    source_fetcher=None,
) -> VersionEstimate | None:
    """按指纹表推断版本。

    ``source_fetcher(rel_path) -> str | None`` 用于 method 级指纹读取源码；
    传 None 时跳过所有 method 级条目（降级为纯类清单比对，精度较低）。
    """
    fps = FINGERPRINTS.get(sdk_name)
    if not fps:
        return None

    est = VersionEstimate(sdk=sdk_name)
    # 上界只采信 reliable 的「缺失」证据，避免 ProGuard 裁剪造成误判
    reliable_upper: str | None = None
    loose_upper: str | None = None
    lower_hit = 0
    upper_hit = 0

    for fp in fps:
        kind = fp["kind"]
        since = fp.get("since")
        until = fp.get("until")
        reliable = bool(fp.get("reliable"))

        if kind == "class":
            present = fp["path"] in class_list
        else:  # method
            if source_fetcher is None:
                continue
            text = source_fetcher(fp["file"])
            if text is None:
                continue  # 宿主类缺失 → 该条不作数（可能被裁剪）
            present = re.search(fp["pattern"], text) is not None

        if present:
            if since:
                if est.lower is None or _vtuple(since) > _vtuple(est.lower):
                    est.lower = since
                lower_hit += 1
                est.hits.append({"feature": fp.get("path") or fp.get("file"),
                                 "present": True, "note": fp["evidence"]})
            if until:
                # 该特征在 until 版本被移除 → 它还「存在」，说明版本早于 until
                if reliable:
                    reliable_upper = until if reliable_upper is None else min(
                        reliable_upper, until, key=_vtuple)
                    upper_hit += 1
                    est.hits.append({"feature": fp.get("path") or fp.get("file"),
                                     "present": True,
                                     "note": f"存在于此 → 版本 < {until}；{fp['evidence']}"})
        else:
            if since:
                if reliable:
                    reliable_upper = since if reliable_upper is None else min(
                        reliable_upper, since, key=_vtuple)
                    upper_hit += 1
                    est.hits.append({"feature": fp.get("path") or fp.get("file"),
                                     "present": False, "note": fp["evidence"]})
                elif loose_upper is None or _vtuple(since) < _vtuple(loose_upper):
                    loose_upper = since

    est.upper = reliable_upper or loose_upper

    # 收敛判定：只有 [lower, upper) 内确实不存在其它发布版本时才给单点结论
    if est.lower and est.upper:
        if _is_patch_successor(est.lower, est.upper):
            est.version = est.lower
            est.upper = None
            est.confidence = "high" if (lower_hit >= 1 and upper_hit >= 2) else "medium"
        elif _vtuple(est.upper) > _vtuple(est.lower):
            # 区间跨越多个补丁版本 → 只能给区间，不给单点
            est.confidence = "medium" if upper_hit else "low"
        else:
            est.confidence = "low"
    elif est.lower:
        est.confidence = "low"

    if not est.lower and not est.upper:
        return None
    return est

# ==============================================================================
# 模块：lib/terminal_renderer.py
# ==============================================================================

# ANSI 颜色（每条元组的 (前景, 背景)）
_COLORS = {
    "RISK":      ("\033[91m", "\033[101m"),  # 亮红
    "CLEAN":     ("\033[92m", "\033[102m"),  # 亮绿
    "MEDIUM":    ("\033[93m", "\033[103m"),  # 亮黄
    "LOW":       ("\033[94m", "\033[104m"),  # 亮蓝
    "HIGH":      ("\033[91m", "\033[101m"),
    "CRITICAL":  ("\033[95m", "\033[105m"),  # 亮品红
    "OK":        ("\033[92m", "\033[102m"),
    "DIM":       "\033[90m",
    "BOLD":      "\033[1m",
    "RESET":     "\033[0m",
    "BG_PACKED": "\033[41;97m",  # 红底白字（加固警告）
    "BG_RISK":   "\033[101;97m",
    "BG_CLEAN":  "\033[42;30m",
}

_VERDICT_LABELS = {
    "RISK": "RISK",
    "CLEAN": "CLEAN",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "OK": "OK",
}

def _ansi(name: str) -> str:
    """获取 ANSI 序列，非 TTY 时返回空串

    注意：_COLORS 中 verdict 类目（RISK/CLEAN/MEDIUM/LOW/HIGH/CRITICAL/OK）
    的值是 (前景, 背景) 元组，此处统一只取前景色，避免元组 repr 泄漏到输出。
    """
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return ""
    val = _COLORS[name]
    return val[0] if isinstance(val, tuple) else val

def _reset() -> str:
    """复位序列：走 _ansi 以确保非 TTY 时不往输出里塞裸转义码"""
    return _ansi("RESET")

def _color(text: str, name: str) -> str:
    c = _ansi(name)
    if not c:
        return text
    return f"{c}{text}{_reset()}"

def _hr(char: str = "─", width: int = 72) -> str:
    return char * width

def _fmt_verdict(verdict: str) -> str:
    label = _VERDICT_LABELS.get(verdict, verdict)
    if verdict == "RISK" or verdict == "HIGH" or verdict == "CRITICAL":
        return _color(f" {label} ", "RISK")
    if verdict == "CLEAN" or verdict == "OK":
        return _color(f" {label} ", "CLEAN")
    if verdict == "MEDIUM":
        return _color(f" {label} ", "MEDIUM")
    if verdict == "LOW":
        return _color(f" {label} ", "LOW")
    return label

def _fmt_packing() -> str:
    """加固红底白字块"""
    c = _ansi("BG_PACKED")
    r = _reset()
    if not c:
        return "[加固样本]"
    return f"{c} ⚠ 加固样本（强行扫描 · 结果不可信） {r}"

class TerminalRenderer:
    """终端报告渲染器

    模式：
      - concise（默认）：只显示 verdict + 有问题的 SDK + CVE + 高危；过滤掉 weak/fw
      - verbose：显示全部 SDK（含弱证据）
    """

    def __init__(self, mode: str = "concise") -> None:
        self.mode = mode  # 'concise' | 'verbose'

    def render(self, report: dict[str, Any]) -> None:
        """终端打印报告"""
        print()
        self._render_header(report)
        self._render_packing(report.get("packing"))
        self._render_summary(report)
        self._render_sdks(report.get("detected_sdks") or [])
        self._render_cves(report.get("cve_matches") or [])
        self._render_high_risk(report.get("high_risk_findings") or [])
        self._render_footer(report)
        print()

    def _render_header(self, report: dict) -> None:
        verdict = report["verdict"]
        b = _ansi("BOLD")
        r = _reset()
        dim = _ansi("DIM")

        print(_hr("═"))
        print(f"{b}APK 第三方组件漏洞扫描报告{r}")
        apk_name = os.path.basename(report["apk"].rstrip("/"))
        print(f"{dim}目标：{apk_name}")
        print(f"扫描时间：{report['scan_time']}")
        print(f"工具链：jadx={report['tool']['used_jadx']}, fallback={report['tool']['used_fallback']}{r}")
        print()
        print(f"判定：{_fmt_verdict(verdict)}  {b}{report['verdict_message']}{r}")
        print(_hr())

    def _render_packing(self, packing: dict | None) -> None:
        if not packing:
            return
        names = " / ".join(packing.get("hardeners", []))
        scores = " / ".join(
            f"{n}:{s}" for n, s in (packing.get("scores") or {}).items()
        )
        b = _ansi("BOLD")
        reset = _reset()
        print()
        print(_fmt_packing())
        print(f"  加固方案：{b}{names}{reset}（评分：{scores}）")
        print(f"  scan_apk_vuln.py step0 已拦截，您使用 --force 跳过——下方数据仅供评估加固厂商 SDK 用。")
        print(f"  建议：脱壳（Fdex / FART / BlackDex）后用 --input-dir 扫描脱壳 dex 目录。")
        ev_lines = []
        for hname, evs in (packing.get("details") or {}).items():
            ev_lines.append(f"    [{hname}] {' · '.join(evs[:6])}")
        if ev_lines:
            print("  证据：")
            for line in ev_lines:
                print(line)
        print(_hr())

    def _render_summary(self, report: dict) -> None:
        s = report["summary"]
        dim = _ansi("DIM")
        reset = _reset()
        print(f"\n{dim}汇总{reset}")
        cards = [
            ("识别 SDK", s.get("sdk_count", 0)),
            ("含 CVE 组件", s.get("vulnerable_components", 0)),
            ("高危类别命中", s.get("high_risk_categories", 0)),
        ]
        for k, v in cards:
            color = "RISK" if "CVE" in k or "高危" in k else "DIM"
            print(f"  {k}：{_color(str(v), color)}")

    def _render_sdks(self, sdks: list[dict]) -> None:
        if not sdks:
            print(f"\n① 识别的 SDK：{_ansi('DIM')}(无){_reset()}")
            return
        print(f"\n① 识别的 SDK ({len(sdks)} 个)")
        # 表头
        print(f"  {'SDK':<24}{'类别':<12}{'版本':<22}{'版本来源':<14}{'匹配':>6}")
        print(f"  {'-'*24}{'-'*12}{'-'*22}{'-'*14}{'-'*6:>6}")
        for s in sdks:
            name = s.get("sdk", "?")[:24]
            cat = s.get("category", "-")[:12]
            ver = (s.get("version") or "未提取")[:22]
            vsrc = s.get("version_source") or "-"
            if vsrc == "fingerprint":
                vsrc_disp = _color("结构推断", "MEDIUM")
            elif vsrc == "exact":
                vsrc_disp = _color("✓ 精确", "CLEAN")
            elif vsrc == "version_constant":
                vsrc_disp = _color("版本常量", "LOW")
            else:
                vsrc_disp = _ansi("DIM") + "未检出" + _reset()
            weak = s.get("weak_evidence", False)
            match = s.get("match_count", "-")
            weak_tag = _color("⚠弱", "RISK") if weak else ""
            # vsrc_disp 已经是带 ANSI 的字符串，宽度计算需用 raw
            raw_vsrc = vsrc
            # 处理 vsrc 含 ANSI 时打印错位：用替代输出
            print(f"  {name:<24}{cat:<12}{ver:<22}{raw_vsrc:<14}{match:>6} {weak_tag}")

    def _render_cves(self, cve_results: list[dict]) -> None:
        if not cve_results:
            print(f"\n② CVE 漏洞匹配：{_color('✓ 未匹配到已知 CVE', 'CLEAN')}")
            return
        print(f"\n② CVE 漏洞匹配 ({len(cve_results)} 个组件)")
        for r in cve_results:
            risk = r.get("risk", "?")
            color = "RISK" if risk == "HIGH" else "MEDIUM"
            print(f"\n  {_color('●', color)} {_ansi('BOLD')}{r['component']}{_reset()} "
                  f"v{r['version']}  [{_color(risk, color)}]")
            for cve in r.get("cves", []):
                cvss = cve.get("cvss_v3") or 0
                cvss_color = "RISK" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
                print(f"      {_color(cve['id'], cvss_color)}  CVSS: {_color(f'{cvss:.1f}' if cvss else 'N/A', cvss_color)}")
                desc = (cve.get("desc") or "")[:160]
                if desc:
                    print(f"        {_ansi('DIM')}{desc}{_reset()}")

    def _render_high_risk(self, findings: list[dict]) -> None:
        if not findings:
            print(f"\n③ 高危组件专项：{_color('✓ 未命中', 'CLEAN')}")
            return
        print(f"\n③ 高危组件专项 ({len(findings)} 类命中)")
        for f in findings:
            sev = f.get("severity", "?")
            color = "RISK" if sev in ("HIGH", "CRITICAL") else "MEDIUM"
            print(f"\n  {_color('▰', color)} {_ansi('BOLD')}{f.get('title', '?')}{_reset()} "
                  f"[{_color(sev, color)}]（{f.get('cve_count', 0)} 条历史 CVE）")
            print(f"      {f.get('description', '')}")
            sdks = ", ".join(f.get("matched_sdks") or []) or "无"
            natives = ", ".join(f.get("matched_native_libs") or []) or "无"
            print(f"      {_ansi('DIM')}命中 SDK：{sdks} | 原生库：{natives}{_reset()}")

    def _render_footer(self, report: dict) -> None:
        s = report["summary"]
        dim = _ansi("DIM")
        print(_hr("─"))
        print(f"{dim}原生库 {s.get('native_lib_count', 0)} 个（未展开） ·  "
              f"本报告由 APK 第三方组件漏洞扫描器自动生成 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{_reset()}")
        print(_hr("═"))

# ==============================================================================
# 模块：lib/txt_report_builder.py
# ==============================================================================

def _hr(char: str = "─", width: int = 72) -> str:
    return char * width

def _row(*cells: str, widths: list[int]) -> str:
    """按列宽左对齐拼一行"""
    out = []
    for i, c in enumerate(cells):
        w = widths[i] if i < len(widths) else 12
        out.append(str(c)[:w].ljust(w))
    return "  ".join(out)

def build_txt(report: dict[str, Any]) -> str:
    lines: list[str] = []
    H1 = _hr("═")
    H2 = _hr("─")

    # === 1. 元数据 ===
    lines.append(H1)
    lines.append("APK 第三方组件漏洞扫描报告")
    lines.append(H2)
    apk = report.get("apk", "?")
    lines.append(f"目标        ：{apk}")
    lines.append(f"扫描时间    ：{report.get('scan_time', '')}")
    tool = report.get("tool", {})
    lines.append(f"工具链      ：jadx={tool.get('used_jadx')}, fallback={tool.get('used_fallback')}")
    lines.append(f"判定        ：{report.get('verdict', '?')} — {report.get('verdict_message', '')}")
    lines.append(H2)

    # === 2. 加固警告 ===
    packing = report.get("packing")
    if packing and packing.get("hardened"):
        lines.append("")
        lines.append("【加固样本警告】")
        names = " / ".join(packing.get("hardeners", []))
        scores = " / ".join(f"{n}:{s}" for n, s in (packing.get("scores") or {}).items())
        lines.append(f"  加固方案   ：{names}（评分：{scores}）")
        lines.append("  ⚠ step0 已拦截，本报告为 --force 强行扫描结果，仅供评估加固厂商 SDK 用。")
        lines.append("  建议       ：脱壳（Fdex / FART / BlackDex）后用 --input-dir 扫描脱壳 dex 目录。")
        for hname, evs in (packing.get("details") or {}).items():
            lines.append(f"  [{hname}] " + " · ".join(evs[:6]))
        lines.append(H2)

    # === 3. 摘要 ===
    s = report.get("summary", {})
    lines.append("")
    lines.append("【汇总】")
    lines.append(f"  识别 SDK        ：{s.get('sdk_count', 0)}")
    lines.append(f"  含 CVE 组件     ：{s.get('vulnerable_components', 0)}")
    lines.append(f"  高危类别命中    ：{s.get('high_risk_categories', 0)}")
    lines.append(f"  原生库 (.so)    ：{s.get('native_lib_count', 0)}")
    lines.append(H2)

    # === 4. SDK 表 ===
    sdks = report.get("detected_sdks") or []
    lines.append("")
    lines.append(f"【① 识别的 SDK】（{len(sdks)} 个）")
    if not sdks:
        lines.append("  （无）")
    else:
        lines.append(_row("SDK", "类别", "版本", "版本来源", "匹配", widths=[24, 12, 22, 14, 6]))
        lines.append(_row("-" * 24, "-" * 12, "-" * 22, "-" * 14, "-" * 6, widths=[24, 12, 22, 14, 6]))
        for s in sdks:
            name = s.get("sdk", "?")[:24]
            cat = s.get("category", "-")[:12]
            ver = (s.get("version") or "未提取")[:22]
            vsrc = s.get("version_source") or "-"
            if vsrc == "exact":
                vsrc = "✓ 精确"
            elif vsrc == "version_constant":
                vsrc = "版本常量"
            elif vsrc == "fingerprint":
                vsrc = "结构推断"
            weak = " ⚠弱" if s.get("weak_evidence") else ""
            fw = " [FW]" if s.get("is_android_framework_lib") else ""
            lines.append(_row(name + weak + fw, cat, ver, vsrc, s.get("match_count", "-"),
                             widths=[24, 12, 22, 14, 6]))
    lines.append(H2)

    # === 5. CVE 列表 ===
    cves = report.get("cve_matches") or []
    lines.append("")
    lines.append(f"【② CVE 漏洞匹配】（{len(cves)} 个组件）")
    if not cves:
        lines.append("  ✓ 未匹配到已知 CVE")
    else:
        for r in cves:
            risk = r.get("risk", "?")
            lines.append(f"  ● {r.get('component')}  v{r.get('version')}  [{risk}]")
            for c in r.get("cves", []):
                cvss = c.get("cvss_v3") or 0
                lines.append(f"      {c.get('id')}  CVSS: {cvss if cvss else 'N/A'}  [{c.get('source', 'NVD')}]")
                desc = (c.get("desc") or "").strip()
                if desc:
                    lines.append(f"        {desc[:200]}")
    lines.append(H2)

    # === 6. 高危专项 ===
    findings = report.get("high_risk_findings") or []
    lines.append("")
    lines.append(f"【③ 高危组件专项】（{len(findings)} 类命中）")
    if not findings:
        lines.append("  ✓ 未命中")
    else:
        for f in findings:
            lines.append(f"  ▰ {f.get('title', '?')}  [{f.get('severity', '?')}]（{f.get('cve_count', 0)} 条历史 CVE）")
            lines.append(f"      {f.get('description', '')}")
            sdks_s = ", ".join(f.get("matched_sdks") or []) or "无"
            natives = ", ".join(f.get("matched_native_libs") or []) or "无"
            lines.append(f"      命中 SDK：{sdks_s} | 原生库：{natives}")
    lines.append(H2)

    # === 7. 原生库摘要 ===
    lines.append("")
    lines.append(f"【原生库】共 {s.get('native_lib_count', 0)} 个（详见 JSON 文件）")
    lines.append("")
    lines.append(f"本报告由 APK 第三方组件漏洞扫描器自动生成 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(H1)

    return "\n".join(lines) + "\n"

# ==============================================================================
# 模块：detect_hardener.py
# ==============================================================================

# 各加固方案的特征类标记（DEX 中明文存在、属壳自身的桩类）
HARDENER_MARKERS = {
    "Bangcle (SecNeo) 梆梆加固": [
        b"com/secneo/apkwrapper/AP",
        b"com/secneo/apkwrapper/AW",
        b"com/secneo/apkwrapper/CP",
        b"com/secneo/apkwrapper/H",
        b"com/secneo/gard",
        b"com/secneo/activity/ProxyActivity",
    ],
    "Qihoo 360 加固": [
        b"com/qihoo/util/St",
        b"com/qihoo/util/Base64",
        b"com/qihoo360/replugin",
    ],
    "Tencent Legu 乐固加固": [
        b"com/tencent/ttp",
        b"com/tencent/StubShell",
        b"com/tencent/StubProxy",
        b"com/tencent/av/anti",
    ],
    "Baidu 百度加固": [
        b"com/baidu/security/anti",
        b"com/baidu/protect",
    ],
    "Payegis / Dingxiang": [
        b"com/payegis/AntiCheat",
        b"com/dingxiang/security",
    ],
    "Pangxie 螃蟹反调试": [
        b"com/pangxie/anti",
    ],
    "iJiami 爱加密": [
        b"com/shell/Encrypt",
        b"com/ijiami/anti",
        b"com/ijiami/client",
    ],
    "NetEase 易盾反外挂": [
        b"com/netease/nis",
        b"com/netease/anti",
    ],
    "Tinker 微信热修复（误判）": [
        b"com/tencent/tinker",
    ],
}

# 加固 .so 文件名模式（路径无关，只匹配 basename）
HARDENER_SO_PATTERNS = {
    "Qihoo 360 加固": [
        b"libjiagu",           # libjiagu.so / libjiagu_a64.so / libjiagu_x64.so / libjiagu_x86.so
        b"libprotectclass",    # 360 新版
        b"libexec",            # 旧版通用壳
    ],
    "Bangcle (SecNeo) 梆梆加固": [
        b"libdexhelper",       # 梆梆脱壳辅助（独特，几乎不冲突）
        b"libsecneo",          # 梆梆壳（独特）
        b"libsecexe",          # 梆梆旧版
        # 注：libsecsdk.so 被字节穿山甲广告 SDK 使用，不是梆梆加固特征，已剔除
    ],
    "Tencent Legu 乐固加固": [
        b"libtup",
        b"libshell",
        b"libmssdk",
    ],
    "iJiami 爱加密": [
        b"libexec",
        b"protectclass",
        b"ijiami",
    ],
    "Baidu 百度加固": [
        b"libbdguard",         # 百度加固加密保护（独有）
        b"libbaiduprotect",    # 百度加固旧版
        # 注：libBaiduMapSDK_*.so 是百度地图 SDK，不是加固，已剔除
    ],
    "Pangxie 螃蟹反调试": [
        b"pxd",
    ],
}

# 加固标志文件（assets/ 下出现的特殊文件，文件名比较用 str）
HARDENER_FLAG_FILES = {
    "Qihoo 360 加固": [
        ".jgapp",              # 360 加固标志性文件
    ],
    "Bangcle (SecNeo) 梆梆加固": [
        "secexe.bin",          # 梆梆加密数据
        "apkwrapper.dat",
    ],
}

# 加权分
WEIGHT_DEX_CLASS = 1      # 每个 DEX 标记类
WEIGHT_SO_NAME = 3        # 匹配加固 .so 文件名
WEIGHT_FLAG_FILE = 5      # 标志文件
THRESHOLD_HARDENED = 3    # 总分 ≥ 3 视为加固

def detect_in_dex(dex_bytes: bytes) -> dict:
    """在单个 dex 字节中检测所有加固标记（阈值降为 1，由上层加权求和）。"""
    found = {}
    for name, markers in HARDENER_MARKERS.items():
        hits = [m.decode("ascii", "ignore") for m in markers if m in dex_bytes]
        if len(hits) >= 1:
            found[name] = hits
    return found

def detect_in_apk(apk_path: Path) -> dict:
    """读 APK 检测加固：DEX 标记类 + 全 .so 文件名（含 assets/）+ 标志文件，加权求和。"""
    try:
        z = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        return {"error": "BadZipFile", "hardened": False}

    scores = defaultdict(int)        # 各加固方案总分
    details = defaultdict(list)      # 各加固方案的命中明细
    matched_so = defaultdict(list)   # 命中的加固 .so
    all_so = []                      # 所有 .so 文件

    for name in z.namelist():
        # 1) DEX 字节匹配标记类
        if name.endswith(".dex"):
            try:
                data = z.read(name)
            except Exception:
                continue
            for hardener, hits in detect_in_dex(data).items():
                scores[hardener] += len(hits) * WEIGHT_DEX_CLASS
                for h in hits:
                    details[hardener].append(f"dex:{name}!{h}")
            continue

        # 2) 所有 .so 文件名（不限 lib/，含 assets/）
        if name.endswith(".so"):
            all_so.append(name)
            base = name.split("/")[-1].lower().encode("ascii", "ignore")
            for hardener, patterns in HARDENER_SO_PATTERNS.items():
                for pat in patterns:
                    if pat in base:
                        scores[hardener] += WEIGHT_SO_NAME
                        details[hardener].append(f"so:{name}")
                        matched_so[hardener].append(name)
                        break

        # 3) 标志文件（如 .jgapp）
        for hardener, flags in HARDENER_FLAG_FILES.items():
            for flag in flags:
                if name.endswith(flag) or name.endswith("/" + flag):
                    scores[hardener] += WEIGHT_FLAG_FILE
                    details[hardener].append(f"flag:{name}")

    # 加权求和 ≥ 阈值视为加固
    hardened = [h for h, s in scores.items() if s >= THRESHOLD_HARDENED]

    # 兼容旧字段
    legacy_suspicious = []
    for h in hardened:
        for so in matched_so[h]:
            if so not in legacy_suspicious:
                legacy_suspicious.append(so)

    return {
        "hardened": len(hardened) > 0,
        "hardeners": hardened,
        "scores": dict(scores),
        "details": {h: details[h] for h in hardened},
        "marker_dex_files": {h: [d for d in details[h] if d.startswith("dex:")] for h in hardened},
        "suspicious_so": legacy_suspicious[:10],
        "matched_so": {h: matched_so[h] for h in hardened},
        "so_count": len(all_so),
    }

# 兼容旧调用点（main 流程 line 3416 使用下划线版本）
_detect_in_apk = detect_in_apk

def main():
    ap = argparse.ArgumentParser(description="加固/混淆检测器")
    ap.add_argument("paths", nargs="+", help="APK 文件或 APK 路径清单文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    targets = []
    for p in args.paths:
        path = Path(p)
        if path.is_file() and path.suffix.lower() == ".apk":
            targets.append(path)
        elif path.is_file() and path.suffix.lower() == ".txt":
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and Path(line).exists():
                    targets.append(Path(line))

    results = {}
    for apk in targets:
        r = detect_in_apk(apk)
        results[apk.name] = r

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    for name, r in results.items():
        print(f"\n=== {name} ===")
        if r.get("error"):
            print(f"  ✘ {r['error']}")
            continue
        print(f"  加固检测: {'已加固 ⚠' if r['hardened'] else '未加固'}")
        if r["hardeners"]:
            for h in r["hardeners"]:
                score = r.get("scores", {}).get(h, "?")
                print(f"     · {h}  (总分 {score})")
                for d in r.get("details", {}).get(h, [])[:5]:
                    print(f"        - {d}")
                if len(r.get("details", {}).get(h, [])) > 5:
                    print(f"        … 等共 {len(r['details'][h])} 项")
        if r["suspicious_so"]:
            print(f"  可疑 .so: {r['suspicious_so'][:3]}")
        print(f"  .so 总数: {r['so_count']}")

    # 汇总
    hardened_n = sum(1 for r in results.values() if r.get("hardened"))
    print(f"\n总计: {hardened_n}/{len(results)} 个 APK 被加固")

    main()

# ==============================================================================
# 模块：scan_apk_vuln.py
# ==============================================================================

# 抑制 androguard 日志噪音
import loguru
loguru.logger.remove()
loguru.logger.add(sys.stderr, level="ERROR")

try:
    from androguard.core.apk import APK
except ImportError:
    print("[!] androguard 未安装，请执行：pip install androguard", file=sys.stderr)
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None  # 仅 NVD 在线模式必需

# 判定「SDK 确实被打包进 APK」所需的最少顶层类数量。
# 低于此阈值通常只是字符串/日志里提到了该库名，而非真的引入了这个库。
# 实测反例：某 App 里只残留 1 个 Glide 内部类（ImageHeaderParser），
#           却没有任何 Glide 主体类 → 不应判定为「使用了 Glide」。
MIN_CLASS_EVIDENCE = 2

# ----------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------

# 全局日志等级控制：默认 quiet（仅 STEP/WARN/FAIL/OK）；--verbose 提升为 INFO 也显示
_LOG_VERBOSE = False

def log(msg: str, level: str = "INFO") -> None:
    """统一日志输出（带颜色前缀 + 时间戳）

    等级过滤（默认 quiet 模式，仅 FAIL 显示）：
      - quiet：仅 FAIL（致命错误，必须看）；STEP/OK/WARN 静默；INFO 静默
      - --verbose：全部显示
    """
    icons = {"INFO": "·", "OK": "✓", "WARN": "!", "FAIL": "✗", "STEP": "▶"}
    icon = icons.get(level, "·")
    if not _LOG_VERBOSE and level not in ("FAIL",):
        return
    print(f"  {icon} {msg}", file=sys.stderr if level == "FAIL" else sys.stdout)

# jadx 常见安装位置（按优先级）。找不到就跳过源码兜底，不影响主流程。
JADX_CANDIDATE_PATHS: list[str] = [
    "~/Desktop/app/测试工具/jadx-1.5.6/bin/jadx",
    "~/Desktop/app/jadx/bin/jadx",
    "/opt/jadx/bin/jadx",
    "/usr/local/jadx/bin/jadx",
    "~/.workbuddy/tools/jadx/bin/jadx",
]

def find_jadx(explicit: str | None = None) -> str | None:
    """定位 jadx 可执行文件。

    查找顺序：
      1. --jadx 显式参数
      2. JADX 环境变量
      3. PATH 上的 jadx
      4. JADX_CANDIDATE_PATHS 常见安装位

    注意：macOS TCC 可能拦截未授权目录的读取/执行（表现为 Operation not permitted）。
    此时需要用户在「系统设置 → 隐私与安全性 → 完全磁盘访问权限」中授权，
    或把 jadx 复制到已授权目录下。
    """
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env_jadx = os.environ.get("JADX")
    if env_jadx:
        candidates.append(env_jadx)
    which_jadx = shutil.which("jadx")
    if which_jadx:
        candidates.append(which_jadx)
    candidates.extend(JADX_CANDIDATE_PATHS)

    for c in candidates:
        if not c:
            continue
        p = Path(c).expanduser()
        # 必须是文件 + 可执行位（不 read，避免触发 TCC 拒绝抛异常）
        try:
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        except OSError:
            continue
    return None

def step(n: int, title: str) -> None:
    """打印步骤标题（quiet 模式下静默）"""
    if not _LOG_VERBOSE:
        return
    print(f"\n[{n}/7] {title}")
    print("-" * (len(title) + 6))

# ----------------------------------------------------------------------
# ① 解压 APK
# ----------------------------------------------------------------------

def step1_unzip(
    apk_path: Path,
    work_dir: Path,
    input_dir: Path | None = None,
) -> dict[str, Any]:
    """解压 APK，列出所有 .so 文件

    参数 input_dir：
      - 显式传入目录时（已脱壳/已解压场景），跳过 unzip 直接使用该目录
      - 否则按 APK 正常解压
    """
    # 目录模式：跳过 unzip，直接使用该目录作为 unpacked_dir
    if input_dir is not None:
        out = input_dir.resolve()
        if not out.is_dir():
            log(f"输入目录不存在：{out}", "FAIL")
            return {"so_files": {}, "unpacked_dir": str(out)}
        log(f"目录模式：直接使用已脱壳目录 {out}", "OK")
    else:
        out = work_dir / "unpacked"
        # 兜底清理（即使主清理因保护机制失败，也不影响 unzip 覆盖解压）
        if out.exists():
            # 先尝试完整清理（大量文件可能触发批量删除保护，故设 ignore_errors）
            try:
                shutil.rmtree(out, ignore_errors=True)
            except Exception:
                pass
            # 兜底：单独清理子项，让 unzip -o 能覆盖
            if out.exists():
                for child in out.iterdir():
                    try:
                        if child.is_dir():
                            shutil.rmtree(child, ignore_errors=True)
                        else:
                            child.unlink()
                    except Exception:
                        pass
        out.mkdir(parents=True, exist_ok=True)

        # 优先用系统 unzip（速度更快）
        if shutil.which("unzip"):
            try:
                subprocess.run(
                    ["unzip", "-q", "-o", str(apk_path), "-d", str(out)],
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                log(f"unzip 失败，回退到 zipfile：{e}", "WARN")
                with zipfile.ZipFile(apk_path) as zf:
                    zf.extractall(out)
        else:
            with zipfile.ZipFile(apk_path) as zf:
                zf.extractall(out)
        log(f"解压完成：{out}", "OK")

    # 列 .so 文件（按架构分组）
    so_files: dict[str, list[str]] = defaultdict(list)
    lib_dir = out / "lib"
    if lib_dir.exists():
        for arch_dir in lib_dir.iterdir():
            if arch_dir.is_dir():
                for so in arch_dir.glob("*.so"):
                    so_files[arch_dir.name].append(so.name)

    log(f"原生库：{sum(len(v) for v in so_files.values())} 个 .so 分布在 "
        f"{len(so_files)} 个架构", "OK")

    return {"so_files": dict(so_files), "unpacked_dir": str(out)}

# ----------------------------------------------------------------------
# ② 反编译（jadx 优先，androguard 兜底）
# ----------------------------------------------------------------------

def step2_decompile(
    apk_path: Path,
    work_dir: Path,
    jadx_path: str | None,
    source_dir: str | None = None,
    input_dir: Path | None = None,
) -> dict[str, Any]:
    """jadx 反编译，失败/缺失时降级为 DEX 字符串提取

    参数 source_dir：
      - 若显式传入，直接使用该目录作为反编译输出
      - 否则解压后自动检测 unpacked/sources/ 是否存在

    参数 input_dir：
      - 目录模式（已脱壳场景），直接扫描该目录下所有 *.dex 抽字符串
      - 跳过 jadx（无 APK 可反编译），直接进入 androguard 兜底路径
    """
    jadx_out = work_dir / "jadx_out"
    used_jadx = False
    used_fallback = False
    actual_source_dir: Path | None = None

    # 目录模式：跳过 jadx，直接走 androguard 兜底
    if input_dir is not None:
        input_dir = input_dir.resolve()
        dex_files = sorted(input_dir.glob("*.dex"))
        dex_dump = work_dir / "dex_strings.txt"
        all_strings: list[str] = []
        for dex_file in dex_files:
            try:
                data = dex_file.read_bytes()
                for s in re.findall(rb"[\x20-\x7e]{6,}", data):
                    all_strings.append(s.decode("ascii", errors="ignore"))
            except Exception as e:
                log(f"读取 {dex_file.name} 失败：{e}", "WARN")
        dex_dump.write_text("\n".join(all_strings), encoding="utf-8")
        used_fallback = True
        log(f"目录模式：扫描 {len(dex_files)} 个 DEX 抽字符串 → {dex_dump}", "OK")
        log(f"提取字符串数：{len(all_strings)}", "OK")

        # v8 新增：自动尝试 jadx 反编译作为版本号兜底
        # 查找顺序：--jadx 参数 > JADX 环境变量 > PATH > JADX_CANDIDATE_PATHS 常见安装位
        jadx_fallback_dir: Path | None = None
        candidate_jadx = find_jadx(jadx_path)
        if not candidate_jadx:
            log("未找到 jadx（可选）：跳过源码兜底，仅用 DEX 字符串提取", "INFO")
            log("  如需启用：--jadx /path/to/jadx  或  export JADX=/path/to/jadx", "INFO")
        if candidate_jadx:
            jadx_fallback_dir = work_dir / "jadx_fallback"
            try:
                jadx_fallback_dir.mkdir(parents=True, exist_ok=True)
                cmd = [
                    candidate_jadx, "-d", str(jadx_fallback_dir),
                    "--no-res",
                    str(input_dir),
                ]
                log(f"自动 jadx 反编译（v8 兜底）：{' '.join(cmd)}", "INFO")
                # 关键：不能用 check=True。jadx 即使成功反编译绝大多数类，
                # 只要有少量类出错就会返回非 0（实测 exit=3，43/5159 个类失败），
                # 此时源码已完整写出，丢弃就太可惜了。改为"看产物不看退出码"。
                proc = subprocess.run(
                    cmd, check=False, capture_output=True,
                    timeout=900,  # 15 分钟上限
                )
                # 统计实际产出的 .java 文件数
                src_root = jadx_fallback_dir / "sources"
                if not src_root.exists():
                    src_root = jadx_fallback_dir
                java_count = sum(1 for _ in src_root.rglob("*.java")) if src_root.is_dir() else 0

                if java_count == 0:
                    log(f"jadx 兜底失败（exit={proc.returncode}）：未产出任何 .java", "WARN")
                    if proc.returncode != 0:
                        log(f"  {proc.stdout.decode(errors='ignore')[-300:]}", "WARN")
                    jadx_fallback_dir = None
                else:
                    log(f"jadx 兜底反编译完成 → {src_root}（{java_count} 个 .java）", "OK")
                    if proc.returncode != 0:
                        # 部分类反编译失败不影响整体使用，提示即可
                        log(f"  注意：jadx 退出码 {proc.returncode}（部分类反编译出错，已保留可用输出）", "WARN")
            except subprocess.TimeoutExpired:
                log("jadx 兜底超时（>15min），跳过", "WARN")
                jadx_fallback_dir = None
            except PermissionError:
                # macOS TCC 拦截未授权目录的执行
                log("jadx 执行被系统权限拦截（macOS TCC）", "WARN")
                log("  处理：系统设置 → 隐私与安全性 → 完全磁盘访问权限，或把 jadx 移到已授权目录", "WARN")
                jadx_fallback_dir = None
            except Exception as e:
                log(f"jadx 兜底异常：{e}", "WARN")
                jadx_fallback_dir = None

        return {
            "used_jadx": False,
            "used_fallback": True,
            "jadx_out_dir": str(jadx_fallback_dir) if jadx_fallback_dir else None,
            "jadx_fallback_dir": str(jadx_fallback_dir) if jadx_fallback_dir else None,
            "actual_source_dir": None,
            "dex_strings": str(dex_dump),
            "input_mode": "dir",
            "dex_file_count": len(dex_files),
        }

    # 优先级 1：用户显式指定
    if source_dir:
        actual_source_dir = Path(source_dir)
        if actual_source_dir.exists():
            used_jadx = True
            log(f"使用用户指定的源码目录：{actual_source_dir}", "INFO")

    # 优先级 2：检测 unpacked/sources（APK 自带源码或上次解包残留）
    if not used_jadx:
        unpacked_sources = work_dir / "unpacked" / "sources"
        if unpacked_sources.exists():
            actual_source_dir = unpacked_sources
            used_jadx = True
            log(f"检测到 APK 内置源码目录：{actual_source_dir}", "INFO")

    # 优先级 3：调用 jadx（自动定位：参数 / 环境变量 / PATH / 常见安装位）
    resolved_jadx = find_jadx(jadx_path)
    if not used_jadx and resolved_jadx:
        jadx_out.mkdir(parents=True, exist_ok=True)
        cmd = [
            resolved_jadx, "-d", str(jadx_out),
            "--no-res",         # 跳过资源，加速
            str(apk_path),
        ]
        log(f"调用 jadx 反编译：{' '.join(cmd)}", "INFO")
        try:
            # 同目录模式：不看退出码，看产物。jadx 少量类失败时仍返回非 0。
            proc = subprocess.run(cmd, check=False, capture_output=True, timeout=600)
            actual_source_dir = jadx_out / "sources"
            if not actual_source_dir.exists():
                actual_source_dir = jadx_out  # 兼容旧版 jadx
            java_count = sum(1 for _ in actual_source_dir.rglob("*.java")) if actual_source_dir.is_dir() else 0
            if java_count == 0:
                log(f"jadx 未产出源码（exit={proc.returncode}），降级为 DEX 字符串提取", "WARN")
                actual_source_dir = None
            else:
                used_jadx = True
                log(f"jadx 反编译完成（{java_count} 个 .java）", "OK")
                if proc.returncode != 0:
                    log(f"  注意：jadx 退出码 {proc.returncode}（部分类出错，已保留可用输出）", "WARN")
        except subprocess.TimeoutExpired:
            log("jadx 超时（>10min），使用兜底方案", "WARN")
        except PermissionError:
            # macOS TCC 拦截未授权目录的执行
            log("jadx 执行被系统权限拦截（macOS TCC）", "WARN")
            log("  处理：系统设置 → 隐私与安全性 → 完全磁盘访问权限，或把 jadx 移到已授权目录", "WARN")
    elif not used_jadx:
        log("未找到可用 jadx，降级为 DEX 字符串提取", "INFO")

    # 兜底：androguard 解析所有 DEX，导出全部字符串
    if not used_jadx:
        dex_dump = work_dir / "dex_strings.txt"
        ap = APK(str(apk_path))
        all_strings: list[str] = []
        for dex in ap.get_all_dex():
            for s in re.findall(rb"[\x20-\x7e]{6,}", dex):
                all_strings.append(s.decode("ascii", errors="ignore"))
        dex_dump.write_text("\n".join(all_strings), encoding="utf-8")
        used_fallback = True
        log(f"未使用 jadx（已降级为 DEX 字符串提取）→ {dex_dump}", "WARN")
        log(f"提取字符串数：{len(all_strings)}", "OK")

    # 提取 DEX class_def 表（真"被定义的类"），与 jadx 产出的 .java 类索引取并集
    #   目的：补全 jadx 因反编译失败/裁剪/混淆而漏掉的类，让"证据不足"判定更精准
    #   仅 APK 模式生效（目录模式由用户自己保证 DEX 完整）
    class_defs_file = work_dir / "dex_class_defs.txt"
    if not used_fallback or used_jadx:
        try:
            ap = APK(str(apk_path))
            class_paths: list[str] = []
            for dex_bytes in ap.get_all_dex():
                # DEX header: magic(8) + checksum(4) + file_size(4) + header_size(4) + ...
                # class_defs_size 在 0x58(class_defs_size) / 0x5c(class_defs_off)
                if len(dex_bytes) < 0x60:
                    continue
                import struct as _s
                n_defs = _s.unpack_from("<I", dex_bytes, 0x58)[0]
                off = _s.unpack_from("<I", dex_bytes, 0x5c)[0]
                # string_ids_size / string_ids_off
                n_str = _s.unpack_from("<I", dex_bytes, 0x38)[0]
                str_off = _s.unpack_from("<I", dex_bytes, 0x3c)[0]
                if n_defs == 0 or off == 0 or n_str == 0:
                    continue
                # string_data_off[]: u32 列表
                string_data_offsets: list[int] = []
                for i in range(n_str):
                    sdo = _s.unpack_from("<I", dex_bytes, str_off + i * 4)[0]
                    string_data_offsets.append(sdo)
                # class_def_item: class_idx(4) + ...  + source_file_idx(4) + ...
                # 我们用 class_idx 解析类型，class_idx 指向 type_ids
                n_type = _s.unpack_from("<I", dex_bytes, 0x40)[0]
                type_off = _s.unpack_from("<I", dex_bytes, 0x44)[0]
                type_desc_idx: list[int] = []
                for i in range(n_type):
                    tdi = _s.unpack_from("<I", dex_bytes, type_off + i * 4)[0]
                    type_desc_idx.append(tdi)
                for i in range(n_defs):
                    class_idx = _s.unpack_from("<I", dex_bytes, off + i * 32)[0]
                    if class_idx >= n_type:
                        continue
                    desc_str_idx = type_desc_idx[class_idx]
                    if desc_str_idx >= n_str:
                        continue
                    sdo = string_data_offsets[desc_str_idx]
                    # string_data: uleb128 length + MUTF-8 bytes
                    pos = sdo
                    # uleb128
                    shift = 0
                    length = 0
                    while True:
                        b = dex_bytes[pos]
                        pos += 1
                        length |= (b & 0x7f) << shift
                        if (b & 0x80) == 0:
                            break
                        shift += 7
                    if length > 0 and length < 512:
                        raw = dex_bytes[pos:pos + length]
                        try:
                            desc = raw.decode("utf-8", errors="ignore")
                            # 形如 Lcom/google/gson/Gson;
                            if desc.startswith("L") and desc.endswith(";"):
                                # 转成类路径（与 jadx .java 路径一致）
                                class_path = desc[1:-1]
                                class_paths.append(class_path)
                        except Exception:
                            pass
            class_defs_file.write_text("\n".join(class_paths), encoding="utf-8")
            log(f"DEX class_def 表提取：{len(class_paths)} 个类 → {class_defs_file}", "INFO")
        except Exception as e:
            log(f"class_def 提取失败（不影响主流程）：{e}", "WARN")

    return {
        "used_jadx": used_jadx,
        "used_fallback": used_fallback,
        "jadx_out_dir": str(jadx_out) if used_jadx else None,
        "actual_source_dir": str(actual_source_dir) if actual_source_dir else None,
        "dex_strings": str(work_dir / "dex_strings.txt") if used_fallback else None,
        "dex_class_defs": str(class_defs_file),
        "input_mode": "apk",
    }

# ----------------------------------------------------------------------
# ③ 搜索 SDK 特征
# ----------------------------------------------------------------------

def step3_search_sdk(dec_info: dict[str, Any]) -> list[dict[str, Any]]:
    """在反编译输出或 DEX 字符串中搜索 SDK 特征

    版本提取策略（按优先级）：
    1. context 局部 hints（最贴近匹配位置）
    2. global_version_patterns（整段文本扫描）
    3. jadx 源码兜底（仅当 1/2 未命中、且 jadx 可用时触发）
    4. 通用 VERSION_REGEX（兜底）

    额外标注：
    - is_android_framework_lib：仅匹配到 Android Framework 系统库引用，
      版本与设备 Android 版本绑定，不进入 CVE 比对
    """
    found: list[dict[str, Any]] = []

    if dec_info["used_jadx"]:
        sources = Path(dec_info["actual_source_dir"])
        if not sources.exists():
            log(f"指定的源码目录不存在：{sources}", "FAIL")
            return found
        # 收集所有 Java 文件内容
        target_texts: list[tuple[str, str]] = []
        for f in sources.rglob("*.java"):
            try:
                target_texts.append((str(f), f.read_text(errors="ignore")))
            except Exception:
                pass
    else:
        dex_str_file = Path(dec_info["dex_strings"])
        target_texts = [(str(dex_str_file), dex_str_file.read_text(errors="ignore"))]

    # 类索引（用于「类是否存在」型指纹 + SDK 存在性强度判定）
    #   jadx 模式：源码目录里每个 .java 就是一个类 ∪ DEX class_def 表（兜底补全 jadx 漏掉的类）
    #   DEX  模式：从 DEX 字符串里抽 Lxxx/yyy; 类型描述符
    src_dir = dec_info.get("actual_source_dir")
    class_index: set[str] = set()
    if src_dir and Path(src_dir).exists():
        base = Path(src_dir)
        for f in base.rglob("*.java"):
            class_index.add(f.relative_to(base).with_suffix("").as_posix())
        # 用 DEX class_def 兜底补全（jadx 反编译失败/被裁剪时不会漏）
        # class_def 表里记录的是 DEX 中**真正被定义**的类，比纯字符串描述符更准
        class_defs_path = dec_info.get("dex_class_defs")
        if class_defs_path and Path(class_defs_path).exists():
            try:
                defs = {line.strip() for line in Path(class_defs_path).read_text(errors="ignore").splitlines() if line.strip()}
                before = len(class_index)
                class_index |= defs
                added = len(class_index) - before
                if added:
                    log(f"  DEX class_def 兜底：补 {added} 个类（jadx 漏掉的）", "INFO")
            except Exception:
                pass
    elif dec_info.get("dex_strings") and Path(dec_info["dex_strings"]).exists():
        class_index = extract_class_list(Path(dec_info["dex_strings"]).read_text(errors="ignore"))
    if class_index:
        log(f"类索引构建完成：{len(class_index)} 个类", "INFO")

    def _source_fetcher(rel_path: str) -> str | None:
        """按源码相对路径取文件内容，供「方法级」指纹使用。"""
        if not src_dir:
            return None
        p = Path(src_dir) / rel_path
        try:
            return p.read_text(errors="ignore")
        except Exception:
            return None

    # 对每个 SDK 特征做正则匹配
    for sdk_name, sig in SDK_SIGNATURES.items():
        matches = []
        global_patterns = sig.get("global_version_patterns", [])
        jadx_patterns = sig.get("jadx_version_patterns", [])
        # 解析 SDK 配置中的 validator 名（"is_chromium_version" -> 函数）
        validator_names = sig.get("global_version_validators", [])
        validators = []
        for vn in validator_names:
            if vn in globals() and callable(globals()[vn]):
                validators.append(globals()[vn])

        # 预先算出「SDK 级版本号」：只算一次，不必每个匹配都重扫全文。
        # 扫描顺序：先扫 SDK 自己的包目录（jadx_package_dirs），再扫全库。
        # 目的：避免别的库里恰好出现的 "okhttp/3.8.0"（比如硬编码的 User-Agent）
        #       抢在 okhttp3 包内的真实版本之前命中，导致拿到错误版本。
        pkg_dirs = sig.get("jadx_package_dirs", [])
        sdk_ver: str | None = None        # 在任意位置找到的版本
        sdk_ver_pkg: str | None = None    # 只在 SDK 自己包目录里找到的版本（最可信）
        if global_patterns:
            in_pkg: list[tuple[str, str]] = []
            out_pkg: list[tuple[str, str]] = []
            if pkg_dirs and len(target_texts) > 1:
                for t in target_texts:
                    if any(d in t[0] for d in pkg_dirs):
                        in_pkg.append(t)
                    else:
                        out_pkg.append(t)
            else:
                out_pkg = list(target_texts)
            # 先只扫 SDK 自己的包目录
            for _, text in in_pkg:
                sdk_ver_pkg = extract_version_global(text, global_patterns, validators)
                if sdk_ver_pkg:
                    break
            # 包内没找到再扫全库
            if not sdk_ver_pkg:
                for _, text in out_pkg:
                    sdk_ver = extract_version_global(text, global_patterns, validators)
                    if sdk_ver:
                        break

        # 收集所有匹配位置用于框架库判定
        all_matched_refs: list[str] = []
        for path, text in target_texts:
            for m in sig["package_pattern"].finditer(text):
                # 命中样本（按 SDK 类型截断前缀）
                ref_sample = m.group(0)
                # 向后找到最近的 ; 结束符 → 类名末尾
                tail_start = m.end()
                tail_end = tail_start
                limit = min(len(text), tail_start + 200)
                while tail_end < limit and text[tail_end] not in (';', ' ', '\n', '\t', ')'):
                    tail_end += 1
                class_name_part = text[tail_start:tail_end]
                # 向前找到最近的 'L'（DEX 类引用起点）或字符串起点
                head_start = m.start()
                while head_start > 0 and text[head_start - 1] not in ('L', ' ', '\n', '\t', '"'):
                    head_start -= 1
                if head_start > 0 and text[head_start - 1] == 'L' and head_start >= m.start() - 100:
                    # 完整 DEX 类引用：Lcom/foo/bar/Class;
                    full_ref = text[head_start - 1:tail_end + (1 if tail_end < len(text) and text[tail_end] == ';' else 0)]
                    # 截断过长（防止性能问题）
                    if len(full_ref) > 300:
                        full_ref = full_ref[:300]
                else:
                    # 无法确定完整引用，使用 ref_sample 自身（按 prefix 判定）
                    full_ref = f"xx{ref_sample}"
                all_matched_refs.append(full_ref)
                # 第一轮：context 局部 hints（最贴近匹配位置）
                ctx = text[max(0, m.start() - 200):min(len(text), m.end() + 400)]
                ver = extract_version(ctx, sig.get("version_hints", []))

                # 第二轮：用预先算好的 SDK 级版本（包内优先）
                if not ver:
                    ver = sdk_ver_pkg or sdk_ver

                matches.append({
                    "file": Path(path).name,
                    "matched": m.group(0),
                    "version_hint": ver,
                })

        # 第三轮：jadx 源码兜底（仅当所有匹配都未拿到版本号时才触发）
        # 两种模式都适用：
        #   APK + jadx 模式  → actual_source_dir（源码本身就是 jadx 产出）
        #   目录 + 兜底模式  → jadx_fallback_dir（额外跑一次 jadx 拿源码）
        jadx_dir = dec_info.get("actual_source_dir") or dec_info.get("jadx_fallback_dir")
        needs_jadx_fallback = (
            (jadx_patterns or sig.get("jadx_int_getter"))
            and jadx_dir
            and matches
            and not any(m["version_hint"] for m in matches)
        )
        if needs_jadx_fallback:
            jadx_pkg_dirs = sig.get("jadx_package_dirs", [])
            jadx_ver = None

            # 3a. 常规源码模式（带包作用域，避免全库误命中）
            if jadx_patterns:
                jadx_ver = extract_version_from_jadx(
                    jadx_dir, sdk_name, jadx_patterns, validators, jadx_pkg_dirs
                )

            # 3b. int getter 提取（AOSP Xalan 这类版本被拆成 int 常量的写法）
            if not jadx_ver and sig.get("jadx_int_getter"):
                jadx_ver, src_file = extract_version_int_getters_from_dir(
                    jadx_dir, jadx_pkg_dirs
                )
                if jadx_ver:
                    log(f"jadx int-getter 提取版本：{sdk_name} → {jadx_ver}（{src_file}）", "OK")

            if jadx_ver:
                # 把版本号回填到所有匹配（同一 SDK 版本号统一）
                for m in matches:
                    if not m["version_hint"]:
                        m["version_hint"] = jadx_ver
                if not sig.get("jadx_int_getter"):
                    log(f"jadx 兜底提取版本：{sdk_name} → {jadx_ver}", "OK")

        # 判定是否为 Android Framework 系统库引用
        # 规则：>=80% 的完整类引用命中 framework hint 即视为 framework 集成
        # （截断标记 xx... 不计入；保护极少数边缘场景下的误判）
        is_framework = is_mostly_android_framework(list(set(all_matched_refs)), threshold=0.8)

        if matches:
            has_exact = any(m["version_hint"] for m in matches)
            # 版本来源：exact（字符串/源码）| version_constant（版本常量）| fingerprint（结构推断）
            version_source: str | None = "exact" if has_exact else None

            # ---- 3.5 版本常量提取（离线高精度，优先级高于指纹） ----
            # 例：Jackson 的 PackageVersion.java 里写着
            #     VERSION = VersionUtil.parseVersion("2.8.7", "com.fasterxml.jackson.core", "jackson-core")
            # 这类常量一旦存在就是最可靠的版本证据。
            if not has_exact and jadx_dir:
                const_ver, const_src = extract_version_constants_from_dir(
                    jadx_dir, sig.get("jadx_package_dirs", [])
                )
                if const_ver:
                    version_source = "version_constant"
                    for m in matches:
                        if not m["version_hint"]:
                            m["version_hint"] = const_ver
                    log(f"版本常量提取：{sdk_name} → {const_ver}（{Path(const_src).name}）", "OK")

            version_candidates = sorted({
                m["version_hint"] for m in matches if m["version_hint"]
            })

            # ---- 3.6 类/方法级结构指纹推断（最后兜底） ----
            # 仅当上述手段都拿不到版本时使用。产出的是**估计值**，
            # 默认不参与 CVE 比对（见 step5 闸门），只作为人工确认线索。
            fp_info: dict[str, Any] | None = None
            if not version_candidates and sdk_name in FINGERPRINTS:
                est = estimate_version(sdk_name, class_index, _source_fetcher)
                if est:
                    version_source = "fingerprint"
                    fp_info = {
                        "version": est.version,
                        "lower": est.lower,
                        "upper": est.upper,
                        "range": est.range_text,
                        "confidence": est.confidence,
                        "evidence": est.hits,
                    }
                    log(
                        f"结构指纹推断：{sdk_name} → {est.range_text}"
                        f"（置信度 {est.confidence}，{len(est.hits)} 条证据）",
                        "OK" if est.version else "WARN",
                    )

            # 首选版本：只认精确来源。
            # 典型反例：App 混淆代码里硬编码 "User-Agent: okhttp/3.8.0"（伪装 UA），
            # 会被 context hints 抓到，但那不是库版本；真实版本在 okhttp3/internal/Version.java。
            preferred: str | None = None
            if version_source != "fingerprint":
                if sdk_ver_pkg and sdk_ver_pkg in version_candidates:
                    preferred = sdk_ver_pkg
                elif len(version_candidates) == 1:
                    preferred = version_candidates[0]

            # ---- SDK 存在性强度判定 ----
            # 只看包名的字符串命中不够：App 日志里提到某个库名、或只剩一个
            # 被裁剪的内部类，都会被误判成「引入了这个库」。
            pkg_top_classes = {
                c.rsplit("/", 1)[-1] for c in class_index
                if "$" not in c.rsplit("/", 1)[-1]
                and sig["package_pattern"].search(c)
            }
            weak_evidence = bool(class_index) and len(pkg_top_classes) < MIN_CLASS_EVIDENCE
            if weak_evidence:
                log(
                    f"证据不足：{sdk_name} 仅有 {len(pkg_top_classes)} 个顶层类"
                    f"（阈值 {MIN_CLASS_EVIDENCE}），疑似外部类型引用或被裁剪的残留类",
                    "WARN",
                )

            found.append({
                "sdk": sdk_name,
                "category": sig["category"],
                "match_count": len(matches),
                "sample_files": list({m["file"] for m in matches})[:5],
                "version_candidates": version_candidates,
                "preferred_version": preferred,
                "version_source": version_source,       # exact / version_constant / fingerprint
                "fingerprint": fp_info,                 # 结构推断明细（含证据链）
                "class_evidence_count": len(pkg_top_classes),
                "weak_evidence": weak_evidence,         # True 表示疑似误命中，报告需提示
                "evidence": matches[:3],  # 保留前 3 条作证据
                "is_android_framework_lib": is_framework,  # 标记 Framework 系统库
            })
            if is_framework:
                log(f"命中 SDK：{sdk_name}（{sig['category']}，{len(matches)} 处，Android Framework 系统库）", "INFO")
            else:
                log(f"命中 SDK：{sdk_name}（{sig['category']}，{len(matches)} 处）", "OK")

    log(f"共识别 SDK/组件：{len(found)} 个", "OK")
    return found

# ----------------------------------------------------------------------
# ④ 检查 META-INF / assets 依赖配置
# ----------------------------------------------------------------------

def step4_check_deps(unpacked_dir: Path) -> list[dict[str, Any]]:
    """在 META-INF/、assets/ 下找 pom.xml / gradle 缓存 / BuildConfig"""
    deps: list[dict[str, Any]] = []
    unpacked = Path(unpacked_dir)

    # 4.1 META-INF/maven 下的 pom.xml（多模块混淆的 Maven 依赖）
    meta_maven = unpacked / "META-INF" / "maven"
    if meta_maven.exists():
        for pom in meta_maven.rglob("pom.xml"):
            try:
                tree = __import__("xml.etree.ElementTree", fromlist=["ET"]).parse(pom)
                root = tree.getroot()
                # 处理 namespace
                ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
                gid = root.findtext("m:groupId", namespaces=ns) or ""
                aid = root.findtext("m:artifactId", namespaces=ns) or ""
                ver = root.findtext("m:version", namespaces=ns) or ""
                deps.append({
                    "source": str(pom.relative_to(unpacked)),
                    "group_id": gid,
                    "artifact_id": aid,
                    "version": ver,
                    "component": f"{gid}:{aid}" if gid else aid,
                })
            except Exception as e:
                deps.append({"source": str(pom), "parse_error": str(e)})

    # 4.2 assets/ 下的 gradle metadata（依赖缓存产物）
    for meta in unpacked.rglob("*.pom"):
        if "META-INF" in str(meta):
            continue
        try:
            text = meta.read_text(errors="ignore")
            for m in re.finditer(
                r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
                text,
            ):
                deps.append({
                    "source": str(meta.relative_to(unpacked)),
                    "group_id": m.group(1),
                    "artifact_id": m.group(2),
                    "version": m.group(3),
                    "component": f"{m.group(1)}:{m.group(2)}",
                })
        except Exception:
            pass

    # 4.3 BuildConfig.java 中的 VERSION_NAME / VERSION_CODE
    build_configs = list(unpacked.rglob("BuildConfig.java"))
    if build_configs:
        for bc in build_configs:
            try:
                text = bc.read_text(errors="ignore")
                ver_name = re.search(r'VERSION_NAME\s*=\s*"([^"]+)"', text)
                ver_code = re.search(r'VERSION_CODE\s*=\s*(\d+)', text)
                if ver_name:
                    deps.append({
                        "source": str(bc.relative_to(unpacked)),
                        "component": "app.BuildConfig",
                        "version": ver_name.group(1),
                        "version_code": ver_code.group(1) if ver_code else None,
                    })
            except Exception:
                pass

    # 4.4 META-INF/<group>_<artifact>.version
    #     Android Gradle Plugin 为每个 AAR 依赖生成的纯文本版本文件，
    #     内容就是版本号本身（如 "27.1.1"）。这是最精确的版本来源——
    #     直接从构建产物里读，不存在正则误匹配问题。
    meta_inf = unpacked / "META-INF"
    if meta_inf.is_dir():
        for vf in meta_inf.glob("*.version"):
            try:
                ver = vf.read_text(errors="ignore").strip()
                if not ver or not re.fullmatch(r"[\w.\-+]+", ver):
                    continue
                # 文件名格式：group_artifact.version（group 里的 "." 被替换成 "_"）
                stem = vf.stem  # 如 com.android.support_appcompat-v7
                if "_" in stem:
                    group, artifact = stem.split("_", 1)
                    group = group.replace("_", ".")
                else:
                    group, artifact = "", stem
                deps.append({
                    "source": str(vf.relative_to(unpacked)),
                    "group_id": group,
                    "artifact_id": artifact,
                    "version": ver,
                    "component": f"{group}:{artifact}" if group else artifact,
                })
            except Exception:
                pass

    # 去重
    seen, uniq = set(), []
    for d in deps:
        key = (d.get("component"), d.get("version"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)

    log(f"提取依赖配置：{len(uniq)} 条", "OK")
    return uniq

# ----------------------------------------------------------------------
# ⑤ NVD CVE 比对
# ----------------------------------------------------------------------

def step5_nvd_check(
    sdks: list[dict[str, Any]],
    deps: list[dict[str, Any]],
    nvd_api_key: str | None,
    cache_dir: Path,
    allow_estimated: bool = False,
) -> list[dict[str, Any]]:
    """将组件 + 版本与 NVD 漏洞库比对

    v8 增强：
      - 跳过 is_android_framework_lib=True 的 SDK（这些是 AOSP 编译进 framework 的系统库，
        版本与设备 Android 版本绑定，App 无法替换，不应作为 App 漏洞判定）

    v10 增强 —— 两道额外的误报闸门：
      - version_source="fingerprint"（结构推断的版本）默认不查 CVE。
        推断值是区间而非精确版本号，直接拿去查 CVE 会产生虚假命中
        （历史教训：某版本曾因模糊版本号一次性产出 20 条虚假 CVE）。
        需人工确认，或用 --aggressive-estimate 显式放行。
      - weak_evidence=True（疑似外部类型引用或被裁剪的残留类）默认不查 CVE。
    """
    checker = CVEChecker(api_key=nvd_api_key, cache_dir=cache_dir)
    results: list[dict[str, Any]] = []

    # 汇总待查组件（SDK + 依赖）
    candidates: dict[str, str] = {}  # component_key -> version
    framework_excluded = 0
    estimate_excluded = 0
    weak_excluded = 0
    for sdk in sdks:
        # v8 跳过 Framework 系统库
        if sdk.get("is_android_framework_lib"):
            framework_excluded += 1
            continue
        # v10 闸门 1：结构推断版本不查 CVE（除非显式放行）
        if sdk.get("version_source") == "fingerprint" and not allow_estimated:
            estimate_excluded += 1
            continue
        # v10 闸门 2：证据不足（疑似误命中）不查 CVE
        if sdk.get("weak_evidence"):
            weak_excluded += 1
            continue
        # 有首选版本时只查首选（避免同一 SDK 因候选版本多而重复报 CVE）；
        # 无首选版本（版本确实无法确定）时保留全部候选，由人工复核。
        pref = sdk.get("preferred_version")
        vers = [pref] if pref else (sdk.get("version_candidates") or [""])
        for ver in vers:
            if ver:
                candidates[f"{sdk['sdk']}@{ver}"] = ver
    for dep in deps:
        comp = dep.get("component", "")
        ver = dep.get("version", "")
        if comp and ver and ver != "unspecified":
            candidates[f"{comp}@{ver}"] = ver

    if framework_excluded:
        log(f"已跳过 {framework_excluded} 个 Android Framework 系统库（AOSP 集成，App 不可控）", "INFO")
    if estimate_excluded:
        log(
            f"已跳过 {estimate_excluded} 个「版本由结构推断」的组件"
            f"（估计值不用于 CVE 比对，需人工确认；--aggressive-estimate 可放行）",
            "WARN",
        )
    if weak_excluded:
        log(f"已跳过 {weak_excluded} 个证据不足的组件（疑似外部类型引用或残留类，非真实依赖）", "WARN")
    log(f"待查组件：{len(candidates)} 个", "INFO")
    for comp_ver, ver in candidates.items():
        cves = checker.lookup(comp_ver)
        if cves:
            results.append({
                "component": comp_ver,
                "version": ver,
                "cves": cves,
                "risk": "HIGH" if any(c["cvss_v3"] and c["cvss_v3"] >= 7.0 for c in cves) else "MEDIUM",
            })
            log(f"  {comp_ver} → {len(cves)} 个 CVE", "OK")
        else:
            log(f"  {comp_ver} → 无已知 CVE", "OK")

    log(f"命中 CVE 的组件：{len(results)} 个", "OK")
    return results

# ----------------------------------------------------------------------
# ⑥ 高危组件专项核查
# ----------------------------------------------------------------------

def step6_high_risk(
    sdks: list[dict[str, Any]],
    so_files: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """加密/网络/WebView/序列化四大类历史高危 CVE 专项

    v8 增强：
      - 跳过 is_android_framework_lib=True 的 SDK（Framework 系统库属于 OS 层风险，
        不算 App 自身漏洞）
    """
    findings: list[dict[str, Any]] = []
    so_names = {so for slist in so_files.values() for so in slist}

    for category, info in HIGH_RISK_CATEGORIES.items():
        cat_hit = False
        # 6.1 检查 SDK 是否包含该类（排除 Framework 系统库）
        sdk_hits = [
            s for s in sdks
            if s["category"] == category
            and not s.get("is_android_framework_lib")
        ]
        # 6.2 检查 .so 名（如 libcrypto / libssl → OpenSSL/BoringSSL）
        so_hits = [s for s in info["so_signals"] if s in so_names]

        if sdk_hits or so_hits:
            cat_hit = True
        if cat_hit:
            findings.append({
                "category": category,
                "title": info["title"],
                "description": info["description"],
                "matched_sdks": [s["sdk"] for s in sdk_hits],
                "matched_native_libs": so_hits,
                "historical_cves": info["historical_cves"],
                "recommendation": info["recommendation"],
                "severity": info["severity"],
            })
            log(f"高危类别命中：{category}（{info['title']}）", "OK")

    return findings

# ----------------------------------------------------------------------
# ⑦ 综合判定 + 报告输出
# ----------------------------------------------------------------------

def _summarize_packing(packing: dict) -> dict | None:
    """精简 detect_in_apk 的返回，只保留 JSON/HTML 需要的字段"""
    if not packing or not packing.get("hardened"):
        return None
    return {
        "hardened": True,
        "hardeners": packing.get("hardeners", []),
        "scores": packing.get("scores", {}),
        "details": packing.get("details", {}),
    }

def step7_report(
    apk_path: Path,
    s1: dict,
    s2: dict,
    sdks: list,
    deps: list,
    cve_results: list,
    high_risk: list,
    report_dir: Path,
    packing: dict | None = None,
    write_files: bool = True,
    output_format: str = "console",
    only_vulnerable: bool = True,
) -> dict[str, Any]:
    """综合所有结果，判定风险等级，输出 JSON / TXT

    仅基于第三方依赖组件的漏洞判定（不做加固识别 / 资产扫描）：
      - CVE 命中或高危组件 → RISK
      - 加固样本强行扫描 → RISK（标注不可信）
      - 否则 → CLEAN

    参数：
      - packing：加固检测结果
      - write_files：是否落盘（默认 True，由 main() 按 --output 决定）
      - output_format：'json' / 'txt' / 'console'，决定写哪种文件
      - only_vulnerable：True=只保留有 CVE / 高危 / 非弱证据的 SDK（默认 True）
    """
    has_cve = bool(cve_results)
    has_high_risk = bool(high_risk)
    is_packed = bool(packing and packing.get("hardened"))

    if is_packed:
        verdict = "RISK"
        verdict_msg = "加固样本强行扫描结果（不可信，仅供参考）"
    elif has_cve or has_high_risk:
        verdict = "RISK"
        verdict_msg = "存在已公开的已知漏洞或高危第三方组件，详见下方清单"
    else:
        verdict = "CLEAN"
        verdict_msg = "未发现已知 CVE 漏洞（不代表 0 漏洞，仍需人工复核）"

    # ---- 精简 SDK 字段（删除干扰项，只保留对决策有用的字段）----
    slim_sdks = []
    for s in sdks:
        is_weak = s.get("weak_evidence", False)
        is_fw = s.get("is_android_framework_lib", False)
        # Framework 系统库始终过滤（版本与设备 Android 版本绑定，不属于 App 依赖）
        if is_fw:
            continue
        # 默认（only_vulnerable=True）：只保留「有真实依赖」的 SDK（去除弱证据）
        # 加固强行扫描场景：保留全部（包括 weak），方便评估加固厂商 SDK
        keep = (
            not only_vulnerable
            or is_packed
            or not is_weak
        )
        if not keep:
            continue
        slim_sdks.append({
            "sdk": s.get("sdk"),
            "category": s.get("category"),
            "version": s.get("preferred_version") or s.get("version"),
            "version_source": s.get("version_source"),
            "weak_evidence": is_weak,
            "is_android_framework_lib": is_fw,
            "match_count": s.get("match_count"),
            "sample_files": (s.get("sample_files") or [])[:3],  # 最多 3 个示例
        })

    # ---- 精简 CVE 字段（截断 desc 长度）----
    slim_cves = []
    for r in cve_results:
        slim_cves.append({
            "component": r.get("component"),
            "version": r.get("version"),
            "risk": r.get("risk"),
            "cves": [
                {
                    "id": c.get("id"),
                    "cvss_v3": c.get("cvss_v3"),
                    "desc": (c.get("desc") or "")[:200],
                    "source": c.get("source", "NVD"),
                }
                for c in r.get("cves", [])
            ],
        })

    # ---- 精简高危发现 ----
    slim_high_risk = []
    for f in high_risk:
        slim_high_risk.append({
            "title": f.get("title"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "matched_sdks": f.get("matched_sdks", []),
            "matched_native_libs": f.get("matched_native_libs", []),
            "cve_count": len(f.get("historical_cves", [])),
        })

    report = {
        "apk": str(apk_path),
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "tool": {
            "used_jadx": s2["used_jadx"],
            "used_fallback": s2["used_fallback"],
        },
        "verdict": verdict,
        "verdict_message": verdict_msg,
        "summary": {
            "sdk_count": len(sdks),
            "vulnerable_components": len(cve_results),
            "high_risk_categories": len(high_risk),
            "native_lib_count": sum(len(v) for v in s1["so_files"].values()),
        },
        "packing": _summarize_packing(packing) if packing else None,
        "detected_sdks": slim_sdks,
        "cve_matches": slim_cves,
        "high_risk_findings": slim_high_risk,
    }

    if write_files:
        report_dir.mkdir(parents=True, exist_ok=True)
        stem = apk_path.stem

        if output_format == "json":
            json_path = report_dir / f"{stem}_vuln.json"
            json_path.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            log(f"JSON 报告：{json_path}", "OK")
        elif output_format == "txt":
            txt_path = report_dir / f"{stem}_vuln.txt"
            txt_path.write_text(build_txt(report), encoding="utf-8")
            log(f"TXT 报告：{txt_path}", "OK")
    return report

# ----------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="APK / 已脱壳目录 第三方组件漏洞自动扫描器",
    )
    parser.add_argument("apk", nargs="?", help="目标 APK 路径（与 --input-dir 二选一）")
    parser.add_argument(
        "--input-dir",
        help="已脱壳 / 已解压目录路径（跳过 unzip，直接扫 *.dex）",
    )
    parser.add_argument(
        "--jadx", help="jadx 可执行文件路径（可选，缺失时自动兜底）"
    )
    parser.add_argument(
        "--source-dir",
        help="已反编译源码目录（跳过步骤 ②，直接进入步骤 ③）；"
             "若 APK 内置 sources/ 也可自动识别",
    )
    parser.add_argument("--nvd-key", help="NVD API Key（推荐，提升速率）")
    parser.add_argument(
        "--work-dir",
        default="./workspace",
        help="工作目录（默认 ./workspace）",
    )
    parser.add_argument(
        "--report-dir",
        default=None,
        help="[已废弃，请改用 --output-dir] 报告输出目录（仅当 --output != console 时生效）",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="保留工作目录（默认扫描后清理）",
    )
    parser.add_argument(
        "--aggressive-estimate",
        action="store_true",
        help="允许用「结构推断」的版本去查 CVE（默认关闭）。"
             "推断值是区间而非精确版本，开启可能产生虚假命中，结果需人工复核。",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="跳过加固检测（强制扫描加固 APK，结果严重不可信，自负风险）。"
             "仅当评估加固厂商 SDK 或确认需要原始数据时才使用。",
    )
    parser.add_argument(
        "--nvd-cache-dir",
        type=Path,
        default=None,
        help="NVD 漏洞缓存目录（默认每次扫描独立子目录）。"
             "批量扫描时建议传入共享目录，避免重复网络请求。",
    )

    # ====== 输出控制（新）======
    parser.add_argument(
        "--output",
        choices=["console", "json", "txt"],
        default="console",
        help="输出形式：console=仅终端打印（默认，不写文件）；"
             "json=终端+JSON 文件；txt=终端+纯文本文件。"
             "注意：扫描摘要（verdict / SDK / CVE）始终打印到终端。",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="文件输出目录（仅当 --output 非 console 时生效）。"
             "不传则与脚本同目录。",
    )

    # ====== 详细度控制（新）======
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="显示进度日志（默认静默，仅显示 STEP/WARN/FAIL/OK）。",
    )
    parser.add_argument(
        "--all-sdks",
        action="store_true",
        help="显示全部 SDK（含证据不足被跳过的）；默认仅显示存在问题的 SDK。",
    )
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="跳过 step5 NVD CVE 比对（用于大批量扫描提速，NVD 限流 5 req/30s 无 Key 时扫描会变慢）。"
             "仅展示 SDK 识别 + 加固检测 + 高危专项，不输出 CVE。",
    )

    args = parser.parse_args()

    # 全局日志等级：默认 quiet，--verbose 提升为全量显示
    global _LOG_VERBOSE
    _LOG_VERBOSE = args.verbose

    # 输入校验：apk 与 --input-dir 必须二选一
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
        if not input_dir.is_dir():
            print(f"[!] 输入目录不存在：{input_dir}", file=sys.stderr)
            return 2
        # 目录模式：用目录本身作为报告主体
        apk_path = input_dir  # 报告里展示路径时用目录路径
        target_label = input_dir.name
    elif args.apk:
        apk_path = Path(args.apk).resolve()
        if not apk_path.is_file():
            print(f"[!] APK 不存在：{apk_path}", file=sys.stderr)
            return 2
        input_dir = None
        target_label = apk_path.name
    else:
        print("[!] 必须提供 APK 文件路径或 --input-dir 目录", file=sys.stderr)
        parser.print_help(sys.stderr)
        return 2

    work_dir = Path(args.work_dir).resolve()
    # --report-dir 已废弃（保留兼容），新参数 --output-dir
    # 不指定时默认与脚本同目录（Path(__file__).parent），不再隐式落到 ./reports
    if args.report_dir is not None:
        report_dir = Path(args.report_dir).resolve()
    elif args.output_dir is not None:
        report_dir = Path(args.output_dir).resolve()
    else:
        report_dir = Path(__file__).resolve().parent
    work_dir.mkdir(parents=True, exist_ok=True)

    # ====== 信号处理：Ctrl+C / kill 也能触发清理（避免 finally 不到时残留）======
    # 收到 SIGINT / SIGTERM 时，先清理 work_dir，再按 Unix 约定以 130 退出
    def _cleanup_and_exit(signum, frame):
        if not args.no_cleanup and not input_dir:
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception as e:
                print(
                    f"\n[!] 信号 {signum} 触发清理失败：{work_dir}\n    请手动删除。错误：{e}",
                    file=sys.stderr,
                )
        # 恢复默认 handler，再抛 KeyboardInterrupt 让 finally 正常退出
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        else:
            sys.exit(128 + signum)

    signal.signal(signal.SIGINT, _cleanup_and_exit)
    signal.signal(signal.SIGTERM, _cleanup_and_exit)

    # 仅在 --output != console 时才建报告目录
    if args.output != "console":
        report_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  APK 第三方组件漏洞扫描器")
    print(f"  目标：{target_label}")
    if input_dir:
        print(f"  模式：目录模式（已脱壳）")
    print(f"{'='*60}")

    # ====== step0：加固检测（合并 detect_hardener.py）======
    # 加固 APK 上 DEX 已加密、业务代码 + 真实 SDK 都被壳遮蔽，
    # 强行扫描会给出假阴性 "CLEAN" 误导用户。默认拒绝扫描，
    # 用户传 --force 才放行（自负风险）。
    apk_hardener_info = None
    if not input_dir and apk_path.is_file():
        try:
            _hard = _detect_in_apk(str(apk_path))
        except Exception as _e:
            log(f"加固检测失败（继续扫描）：{_e}", "WARN")
            _hard = None
        if _hard and _hard.get("hardened"):
            names = " / ".join(_hard.get("hardeners", []))
            scores = " / ".join(
                f"{n}:{s}" for n, s in _hard.get("scores", {}).items()
            )
            print(f"\n[!] 检测到加固样本：{names}（评分 {scores}）")
            for hname, evs in _hard.get("details", {}).items():
                print(f"    证据：{'  '.join(evs[:6])}")
            print(f"\n    加固 APK 上静态扫描严重不可信：")
            print(f"      - DEX 已加密，业务代码 + 真实 SDK 都被壳遮蔽")
            print(f"      - jadx 只能反编译出 4 个桩类，几乎不会命中任何 SDK")
            print(f"      - 强行扫描会给出假阴性 \"CLEAN\"，误导为「已检查且安全」")
            print(f"\n    处置建议（按优先级）：")
            print(f"      1. 先脱壳（Fdex / FART / BlackDex），再传 --input-dir 扫描脱壳后的 dex 目录")
            print(f"      2. 仅评估加固方案本身的安全风险，参考 detect_hardener.py 报告")
            print(f"      3. 确实需要强行扫描（如评估加固厂商 SDK），传 --force 跳过此检查\n")
            if not args.force:
                print(f"    已退出（未传 --force）。\n")
                return 2
            print(f"    --force 已启用，继续扫描（结果仅供参考）。\n")
            apk_hardener_info = _hard

    try:
        step(1, "解压 APK 并列出原生库" if not input_dir else "扫描已脱壳目录并列出原生库")
        s1 = step1_unzip(apk_path, work_dir, input_dir)

        step(2, "反编译（jadx 优先，androguard 兜底）" if not input_dir else "DEX 字符串提取（目录模式跳过 jadx）")
        s2 = step2_decompile(apk_path, work_dir, args.jadx, args.source_dir, input_dir)

        step(3, "搜索 SDK 包名特征")
        sdks = step3_search_sdk(s2)

        step(4, "提取 META-INF / assets 依赖配置")
        deps = step4_check_deps(Path(s1["unpacked_dir"]))

        cache_dir = args.nvd_cache_dir if args.nvd_cache_dir else (work_dir / "nvd_cache")
        if args.skip_nvd:
            log("已跳过 NVD CVE 比对（--skip-nvd）", "INFO")
            cve_results = []
        else:
            step(5, "NVD CVE 漏洞库比对")
            cve_results = step5_nvd_check(
                sdks, deps, args.nvd_key, cache_dir,
                allow_estimated=args.aggressive_estimate,
            )

        step(6, "高危组件专项核查")
        high_risk = step6_high_risk(sdks, s1["so_files"])

        step(7, "综合判定 + 报告输出")
        report = step7_report(
            apk_path, s1, s2, sdks, deps, cve_results, high_risk, report_dir,
            packing=apk_hardener_info,
            write_files=False,
            only_vulnerable=not args.all_sdks,
        )
    finally:
        if not args.no_cleanup and not input_dir:
            # 目录模式不清理（输入即用户原始数据）
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception as e:
                # 不再静默吞错：让用户能感知"清理失败"
                log(f"清理失败：{work_dir}（请手动删除）。错误：{e}", "WARN")
            else:
                log("已清理工作目录", "INFO")

    # ====== 终端输出（始终）======
    TerminalRenderer(mode="verbose" if args.all_sdks else "concise").render(report)

    # ====== 文件输出（按 --output 决定）======
    if args.output == "json":
        json_path = report_dir / f"{apk_path.stem}_vuln.json"
        json_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        log(f"JSON 报告：{json_path}", "OK")
    elif args.output == "txt":
        txt_path = report_dir / f"{apk_path.stem}_vuln.txt"
        txt_path.write_text(build_txt(report), encoding="utf-8")
        log(f"TXT 报告：{txt_path}", "OK")

    if args.output == "console":
        log(f"仅终端输出（未写文件，--output {args.output}）。如需保存，加 --output json|txt", "INFO")
    else:
        log(f"文件目录：{report_dir}", "INFO")

    # 退出码：CLEAN=0, RISK=1
    return {"CLEAN": 0, "RISK": 1}[report["verdict"]]

if __name__ == "__main__":
    sys.exit(main())

