#!/usr/bin/env python3
"""
repackage.py - 月圆之夜 APK 重打包工具

将 libgoldhack.so 注入到 APK 中，并在 Application 类的 attachBaseContext 中
调用 System.loadLibrary("goldhack") 使其自动加载。

关键：精确保持每个文件原始的压缩方式（STORE/DEFLATE），
      否则 Unity 引擎会报 "Unknown compression method" 导致黑屏。

用法:
    python3 repackage.py                          # 使用默认路径
    python3 repackage.py --apk /path/to/orig.apk  # 指定原始 APK
    python3 repackage.py --so /path/to/lib.so      # 指定 .so 文件
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== 路径配置 ====================

DEFAULT_APK = os.path.join(SCRIPT_DIR, '..', '月圆之夜_1.6.28.apk')
DEFAULT_SO = os.path.join(SCRIPT_DIR, 'libgoldhack.so')
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, '月圆之夜_modded.apk')

TOOLS_DIR = os.path.join(SCRIPT_DIR, "tools")
SIGSPOOF_SMALI_DIR = os.path.join(SCRIPT_DIR, "sigspoof_smali")
BAKSMALI_JAR = os.path.join(TOOLS_DIR, "baksmali.jar")
SMALI_JAR = os.path.join(TOOLS_DIR, "smali.jar")
KEYSTORE = os.path.join(TOOLS_DIR, "debug.keystore")
KEY_ALIAS = "debug"
KEY_PASS = "android"

# baksmali/smali 下载地址 (多个备选)
BAKSMALI_URLS = [
    "https://github.com/JesusFreke/smali/releases/download/v2.5.2/baksmali-2.5.2.jar",
    "https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar",
]
SMALI_URLS = [
    "https://github.com/JesusFreke/smali/releases/download/v2.5.2/smali-2.5.2.jar",
    "https://bitbucket.org/JesusFreke/smali/downloads/smali-2.5.2.jar",
]
JAR_MIN_SIZE = 100_000  # 合法 jar 至少 100KB


def find_build_tools():
    """查找 Android SDK build-tools"""
    sdk = os.path.expanduser("~/Library/Android/sdk")
    bt_dir = os.path.join(sdk, "build-tools")
    if not os.path.isdir(bt_dir):
        # Linux 路径
        sdk = os.path.expanduser("~/Android/Sdk")
        bt_dir = os.path.join(sdk, "build-tools")
    if not os.path.isdir(bt_dir):
        return None
    for d in sorted(os.listdir(bt_dir), reverse=True):
        p = os.path.join(bt_dir, d)
        if os.path.isfile(os.path.join(p, "apksigner")):
            return p
    return None


BUILD_TOOLS = find_build_tools()


# ==================== 工具管理 ====================

def download_file(urls, dest):
    """从多个 URL 尝试下载文件（优先用 curl 避免 SSL 问题）"""
    for url in urls:
        try:
            print(f"    尝试: {url}")
            # 优先用 curl（macOS 自带，不受 Python SSL 证书问题影响）
            r = subprocess.run(
                ["curl", "-L", "-o", dest, url],
                capture_output=True, timeout=300
            )
            if r.returncode == 0 and os.path.isfile(dest) and os.path.getsize(dest) > JAR_MIN_SIZE:
                return True
            if os.path.exists(dest):
                os.remove(dest)
        except Exception as e:
            print(f"    失败: {e}")
            if os.path.exists(dest):
                os.remove(dest)
    return False


def ensure_tools():
    """确保 baksmali、smali、keystore 都可用"""
    os.makedirs(TOOLS_DIR, exist_ok=True)

    # baksmali
    if not os.path.isfile(BAKSMALI_JAR) or os.path.getsize(BAKSMALI_JAR) < JAR_MIN_SIZE:
        print("  下载 baksmali.jar ...")
        if not download_file(BAKSMALI_URLS, BAKSMALI_JAR):
            print("  ❌ 无法下载 baksmali.jar")
            print(f"     请手动下载到: {BAKSMALI_JAR}")
            sys.exit(1)

    # smali
    if not os.path.isfile(SMALI_JAR) or os.path.getsize(SMALI_JAR) < JAR_MIN_SIZE:
        print("  下载 smali.jar ...")
        if not download_file(SMALI_URLS, SMALI_JAR):
            print("  ❌ 无法下载 smali.jar")
            print(f"     请手动下载到: {SMALI_JAR}")
            sys.exit(1)

    # debug keystore
    if not os.path.isfile(KEYSTORE):
        print("  创建 debug keystore ...")
        subprocess.run([
            "keytool", "-genkeypair",
            "-keystore", KEYSTORE,
            "-alias", KEY_ALIAS,
            "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-storepass", KEY_PASS, "-keypass", KEY_PASS,
            "-dname", "CN=Debug,OU=Debug,O=Debug,L=Debug,ST=Debug,C=US"
        ], check=True, capture_output=True)

    # 验证 java
    r = subprocess.run(["java", "-version"], capture_output=True, text=True)
    if r.returncode != 0:
        print("  ❌ java 未安装")
        sys.exit(1)


# ==================== Manifest 解析 ====================

def find_app_class(apk_path):
    """从 AndroidManifest.xml 查找 Application 类名"""
    if not BUILD_TOOLS:
        return None

    aapt2 = os.path.join(BUILD_TOOLS, "aapt2")
    if os.path.isfile(aapt2):
        try:
            r = subprocess.run(
                [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
                capture_output=True, text=True, timeout=15
            )
            in_app = False
            pkg_name = None
            for line in r.stdout.split('\n'):
                # 获取包名
                m = re.search(r'package="([^"]+)"', line)
                if m:
                    pkg_name = m.group(1)
                # 进入 application 节点
                if 'E: application' in line:
                    in_app = True
                elif in_app and 'android:name' in line:
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        cls = m.group(1)
                        if cls.startswith('.') and pkg_name:
                            cls = pkg_name + cls
                        return cls
                elif in_app and re.match(r'\s+E:', line) and 'application' not in line:
                    break
        except Exception:
            pass

    return None


def find_main_activity(apk_path):
    """查找主 Activity"""
    if not BUILD_TOOLS:
        return None

    aapt2 = os.path.join(BUILD_TOOLS, "aapt2")
    if os.path.isfile(aapt2):
        try:
            r = subprocess.run(
                [aapt2, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=15
            )
            for line in r.stdout.split('\n'):
                if 'launchable-activity' in line:
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass

    return None


# ==================== 签名伪造 ====================

def extract_original_cert(apk_path):
    """
    从原始 APK 提取签名证书的 DER 编码（hex 字符串）。
    这与 Android PackageManager.getPackageInfo().signatures[0].toCharsString() 等价。
    """
    cert_file = None
    with zipfile.ZipFile(apk_path, 'r') as z:
        for name in z.namelist():
            if name.startswith('META-INF/') and (
                    name.endswith('.RSA') or name.endswith('.DSA') or name.endswith('.EC')):
                cert_file = name
                break
        if not cert_file:
            return None
        pkcs7_data = z.read(cert_file)

    # PKCS#7 DER → PEM
    r1 = subprocess.run(
        ['openssl', 'pkcs7', '-inform', 'DER', '-print_certs'],
        input=pkcs7_data, capture_output=True
    )
    if r1.returncode != 0:
        return None

    # PEM → DER
    r2 = subprocess.run(
        ['openssl', 'x509', '-inform', 'PEM', '-outform', 'DER'],
        input=r1.stdout, capture_output=True
    )
    if r2.returncode != 0 or len(r2.stdout) < 100:
        return None

    return r2.stdout.hex()


def copy_sigspoof_smali(smali_dir):
    """
    将预编译的 SigSpoof smali 文件复制到 smali 工作目录。
    """
    if not os.path.isdir(SIGSPOOF_SMALI_DIR):
        print(f"  ❌ 找不到签名伪造 smali 目录: {SIGSPOOF_SMALI_DIR}")
        return False

    dst_dir = os.path.join(smali_dir, 'com', 'hook')
    os.makedirs(dst_dir, exist_ok=True)

    count = 0
    for root, dirs, files in os.walk(SIGSPOOF_SMALI_DIR):
        for f in files:
            if f.endswith('.smali'):
                src = os.path.join(root, f)
                rel = os.path.relpath(src, SIGSPOOF_SMALI_DIR)
                dst = os.path.join(smali_dir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                count += 1

    print(f"  复制 {count} 个签名伪造 smali 文件")
    return count > 0


# ==================== Smali 注入 ====================

def inject_loadlibrary(smali_dir, class_name, lib_name="goldhack", cert_hex=None):
    """
    在目标类的 smali 中注入 System.loadLibrary 调用。
    优先注入到 attachBaseContext (super 调用之后)，
    其次 onCreate，最后 fallback 到添加 <clinit>。
    """
    smali_rel = class_name.replace('.', '/') + '.smali'
    smali_path = os.path.join(smali_dir, smali_rel)

    if not os.path.isfile(smali_path):
        print(f"  ❌ 找不到 smali 文件: {smali_rel}")
        # 列出可能的候选
        base = class_name.split('.')[-1]
        for root, dirs, files in os.walk(smali_dir):
            for f in files:
                if base in f:
                    rel = os.path.relpath(os.path.join(root, f), smali_dir)
                    print(f"     候选: {rel}")
        return False

    with open(smali_path, 'r') as f:
        lines = f.readlines()

    # 检查是否已注入
    content = ''.join(lines)
    if f'"{lib_name}"' in content and 'System;->loadLibrary' in content:
        print(f"  ⏭  已经注入过，跳过")
        return True

    # 尝试在 attachBaseContext / onCreate 中注入
    for method_name in ['attachBaseContext', 'onCreate']:
        method_idx = -1
        locals_idx = -1
        locals_val = 0
        super_call_idx = -1

        for i, line in enumerate(lines):
            stripped = line.strip()

            if method_idx < 0:
                if '.method' in stripped and f'{method_name}(' in stripped:
                    method_idx = i
            else:
                if stripped.startswith('.locals '):
                    locals_idx = i
                    locals_val = int(stripped.split()[1])
                    is_registers = False
                elif stripped.startswith('.registers '):
                    locals_idx = i
                    locals_val = int(stripped.split()[1])
                    is_registers = True
                elif 'invoke-' in stripped and f'->{method_name}(' in stripped:
                    super_call_idx = i
                elif stripped == '.end method':
                    break

        if method_idx < 0 or super_call_idx < 0:
            continue

        # 分配一个安全的新寄存器
        if is_registers:
            # .registers N 包含参数寄存器，增加1后用 v(N-params)
            # 参数: p0(this) + 方法参数
            # 对 attachBaseContext(Context): 2个参数 (this + context)
            # 对 onCreate(Bundle): 2个参数 (this + bundle)
            # 对 onCreate(): 1个参数 (this)
            # 计算参数数量: 从方法签名推断
            method_line = lines[method_idx].strip()
            param_sig = method_line.split('(')[1].split(')')[0] if '(' in method_line else ''
            # 计算参数槽位: 每个 L...;/[... 占1个, J/D占2个
            n_params = 1  # this
            j = 0
            while j < len(param_sig):
                c = param_sig[j]
                if c == 'L':
                    n_params += 1
                    j = param_sig.index(';', j) + 1
                elif c == '[':
                    j += 1  # skip array prefix
                elif c in ('J', 'D'):
                    n_params += 2
                    j += 1
                else:
                    n_params += 1
                    j += 1

            n_locals = locals_val - n_params
            new_reg_num = n_locals  # 新寄存器编号 = 当前本地寄存器数
            reg = f'v{new_reg_num}'
            new_total = locals_val + 1
            lines[locals_idx] = lines[locals_idx].replace(
                f'.registers {locals_val}', f'.registers {new_total}')
        else:
            # .locals N — 直接加1
            new_locals = locals_val + 1
            reg = f'v{locals_val}'
            lines[locals_idx] = lines[locals_idx].replace(
                f'.locals {locals_val}', f'.locals {new_locals}')

        # 在 super 调用之后插入代码
        inject = []

        # 1) 签名伪造（如果提供了证书 hex）
        if cert_hex:
            inject.extend([
                f'    const-string {reg}, "{cert_hex}"\n',
                f'    invoke-static {{p0, {reg}}}, Lcom/hook/SigSpoof;->install(Landroid/content/Context;Ljava/lang/String;)V\n',
            ])

        # 2) loadLibrary
        inject.extend([
            f'    const-string {reg}, "{lib_name}"\n',
            f'    invoke-static {{{reg}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n',
        ])

        insert_pos = super_call_idx + 1
        for j, inject_line in enumerate(inject):
            lines.insert(insert_pos + j, inject_line)

        with open(smali_path, 'w') as f:
            f.writelines(lines)

        print(f"  ✅ 注入到 {class_name}.{method_name}()  寄存器={reg}")
        return True

    # Fallback: 添加 <clinit> 静态初始化块
    print(f"  ⚠ 未找到 attachBaseContext/onCreate，添加 <clinit>")

    # 检查是否已有 <clinit>
    if '.method static constructor <clinit>()V' in content:
        # 在已有 <clinit> 开头注入
        for i, line in enumerate(lines):
            if '<clinit>' in line and '.method' in line:
                # 找到 .locals 行
                for j in range(i + 1, min(i + 10, len(lines))):
                    stripped = lines[j].strip()
                    if stripped.startswith('.locals') or stripped.startswith('.registers'):
                        val = int(stripped.split()[1])
                        if val < 1:
                            lines[j] = lines[j].replace(stripped, '.locals 1')
                        inject = [
                            f'    const-string v0, "{lib_name}"\n',
                            f'    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n',
                        ]
                        for k, il in enumerate(inject):
                            lines.insert(j + 1 + k, il)
                        break
                break
    else:
        clinit = (
            '\n'
            '.method static constructor <clinit>()V\n'
            '    .registers 1\n'
            f'    const-string v0, "{lib_name}"\n'
            f'    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
            '    return-void\n'
            '.end method\n'
        )
        # 插入到第一个 .method 之前
        insert_pos = len(lines)
        for i, line in enumerate(lines):
            if line.strip().startswith('.method '):
                insert_pos = i
                break
        lines.insert(insert_pos, clinit)

    with open(smali_path, 'w') as f:
        f.writelines(lines)

    print(f"  ✅ 注入 <clinit> 到 {class_name}")
    return True


# ==================== libil2cpp.so 二进制补丁 ====================

# ==================== 二进制补丁 ====================
#
# MHP v3.5.0 有两个关键回调机制：
#
# 1. 解密回调: 在 sub_F7E260 中通过虚函数回调解密 global-metadata.dat
#    回调使用基于 APK 签名的密钥，重签后失效。
#
# 2. 初始化回调: 在 sub_F74B78 中通过 off_43A0130 调用 MHP 获取
#    CodeRegistration/MetadataRegistration 结构地址，然后通过 sub_F848F4
#    设置 5 个全局指针（qword_4659C30/C38/465A1F8/465A200/465A208）。
#
# 关键发现：注册结构数据已经存在于 libil2cpp.so 的 .data 段中，
# 且有 R_AARCH64_RELATIVE 重定位条目，动态链接器会自动修正指针。
# MHP 的作用只是提供地址给全局变量。
#
# 补丁策略：
#   Patch #1: 跳过解密回调，使用预解密的 metadata
#   Patch #2: 绕过 MHP init 回调，用 ADRP/ADD 直接计算结构地址

# ---- Patch #1: 解密回调跳过 ----
# MHP 在 sub_F7E260 中通过虚函数回调解密 metadata，补丁为直接跳过
PATCH1_OFFSET = 0xf7e300
PATCH1_ORIG = bytes.fromhex('080140f9a2a300d1e00315aa080540f900013fd6')
PATCH1_NEW = bytes.fromhex('b5831df8' + '1f2003d5' * 4)

# ---- Patch #2: 初始化回调绕过 ----
# MHP 有第二个回调用于设置 CodeRegistration/MetadataRegistration 全局指针。
# 原始流程: sub_F74B78 → MHP init callback (off_43A0130) → sub_F848F4 → sub_C96774 (MHP thunks)
# 补丁后:   sub_F74B78 → BL sub_F848F4 → code_cave (ADRP/ADD 计算地址) → 设置全局指针
#
# 注册结构数据已经在 libil2cpp.so 中，有 R_AARCH64_RELATIVE 重定位，
# 动态链接器会自动修正指针。我们只需跳过 MHP 回调，直接设置全局变量。
#
# Part A: 调用点绕过 (sub_F74B78 中 0xF74C90-0xF74C9C)
#   原始: ADRP+LDR+LDR+BLR (调用 MHP init callback)
#   补丁: NOP×3 + BL sub_F848F4
PATCH2A_OFFSET = 0xF74C90
PATCH2A_ORIG = bytes.fromhex('68a10190089940f9080140f900013fd6')
PATCH2A_NEW = bytes.fromhex('1f2003d51f2003d51f2003d5163f0094')

# Part B: sub_F848F4 入口重定向
#   原始: BL sub_C96774 (调用 MHP thunks 获取注册结构)
#   补丁: B code_cave (跳转到 code cave 直接计算地址)
PATCH2B_OFFSET = 0xF848F4
PATCH2B_ORIG = bytes.fromhex('a047f497')
PATCH2B_NEW = bytes.fromhex('e561f517')

# Part C: Code cave (0xcdd088, 文本段中的空闲区域)
#   7条指令: ADRP/ADD 加载 MetaReg/CodeReg/Extra 地址到 X0/X1/X2, 然后 B 回
#   0xcdd088: ADRP X0, #0x4338000    ; MetadataRegistration @ 0x4338F60
#   0xcdd08c: ADD  X0, X0, #0xF60
#   0xcdd090: ADRP X1, #0x4339000    ; CodeRegistration @ 0x4339F70
#   0xcdd094: ADD  X1, X1, #0xF70
#   0xcdd098: ADRP X2, #0x36A6000    ; ExtraPtr @ 0x36A649C
#   0xcdd09c: ADD  X2, X2, #0x49C
#   0xcdd0a0: B    0xF848F8           ; 跳回 sub_F848F4 的 ADRP/STR 部分
PATCH2C_OFFSET = 0xcdd088
PATCH2C_ORIG = bytes(28)  # 28 bytes of zeros (code cave)
PATCH2C_NEW = bytes.fromhex('c0b201f000803d91e1b2019021c03d91424e01b042701291169e0a14')

# 旧的兼容别名
PATCH_OFFSET = PATCH1_OFFSET
PATCH_ORIG = PATCH1_ORIG
PATCH_NEW = PATCH1_NEW

DECRYPTED_METADATA_PATH = os.path.join(SCRIPT_DIR, '..', 'decrypted_output', 'global-metadata.dat')
MHP_HEADER_PATH = os.path.join(SCRIPT_DIR, '..', 'decrypted_output', 'mhp_header.bin')
METADATA_MAGIC = 0xFAB11BAF
MHP_HEADER_SIZE = 256  # MHP 创建的自定义头部大小（字段偏移重排）


def _apply_patch(so_bytes, offset, orig, new, desc):
    """应用单个补丁，返回是否成功"""
    actual = bytes(so_bytes[offset:offset + len(orig)])
    if actual != orig:
        print(f"  ❌ {desc}: 校验失败！")
        print(f"     偏移: 0x{offset:x}")
        print(f"     期望: {orig.hex()}")
        print(f"     实际: {actual.hex()}")
        return False
    so_bytes[offset:offset + len(new)] = new
    print(f"  ✅ {desc} @ 0x{offset:x}")
    return True


def patch_libil2cpp(so_data):
    """
    补丁 libil2cpp.so：
      Patch #1: 跳过 MHP 的 metadata 解密回调
      Patch #2: 绕过 MHP 的初始化回调，直接设置注册结构全局指针
    返回补丁后的字节数据，或 None 表示失败。
    """
    so_bytes = bytearray(so_data)

    # Patch #1: 解密回调跳过
    if not _apply_patch(so_bytes, PATCH1_OFFSET, PATCH1_ORIG, PATCH1_NEW,
                        "Patch #1: 跳过 MHP 解密回调"):
        return None

    # Patch #2A: 调用点绕过
    if not _apply_patch(so_bytes, PATCH2A_OFFSET, PATCH2A_ORIG, PATCH2A_NEW,
                        "Patch #2A: 调用点绕过 MHP init callback"):
        return None

    # Patch #2B: sub_F848F4 重定向到 code cave
    if not _apply_patch(so_bytes, PATCH2B_OFFSET, PATCH2B_ORIG, PATCH2B_NEW,
                        "Patch #2B: sub_F848F4 → code cave"):
        return None

    # Patch #2C: 写入 code cave 代码
    if not _apply_patch(so_bytes, PATCH2C_OFFSET, PATCH2C_ORIG, PATCH2C_NEW,
                        "Patch #2C: code cave (计算注册结构地址)"):
        return None

    print(f"  ✅ 全部 4 个补丁已应用")
    return bytes(so_bytes)


def load_decrypted_metadata():
    """加载预解密的 global-metadata.dat，并用 MHP 头部替换前 256 字节。
    
    MHP 保护不仅解密 metadata 数据体，还会创建一个自定义的头部结构，
    将各字段偏移量重新排列。il2cpp 代码读取 header+48 等特定偏移处的值，
    如果使用原始（加密的）头部，偏移量会指向错误位置导致 SIGSEGV。
    
    解决方案：用 Frida 从原始游戏捕获 MHP 解密后的头部（256字节），
    替换到我们的预解密 metadata 文件中。
    """
    path = DECRYPTED_METADATA_PATH
    if not os.path.isfile(path):
        print(f"  ❌ 找不到解密的 metadata: {path}")
        return None

    with open(path, 'rb') as f:
        data = bytearray(f.read())

    # 验证 magic
    import struct
    magic = struct.unpack('<I', data[:4])[0]
    if magic != METADATA_MAGIC:
        print(f"  ❌ metadata magic 不匹配: {hex(magic)} (期望 {hex(METADATA_MAGIC)})")
        return None

    # 替换头部为 MHP 解密后的头部
    if os.path.isfile(MHP_HEADER_PATH):
        with open(MHP_HEADER_PATH, 'rb') as f:
            mhp_header = f.read()
        if len(mhp_header) == MHP_HEADER_SIZE:
            mhp_magic = struct.unpack('<I', mhp_header[:4])[0]
            if mhp_magic == METADATA_MAGIC:
                data[:MHP_HEADER_SIZE] = mhp_header
                print(f"  ✅ 已用 MHP 头部替换前 {MHP_HEADER_SIZE} 字节（字段偏移重排）")
            else:
                print(f"  ⚠️  MHP 头部 magic 不匹配: {hex(mhp_magic)}")
        else:
            print(f"  ⚠️  MHP 头部大小异常: {len(mhp_header)} (期望 {MHP_HEADER_SIZE})")
    else:
        print(f"  ⚠️  找不到 MHP 头部: {MHP_HEADER_PATH}")
        print(f"      metadata 将使用原始头部，可能导致崩溃！")

    print(f"  ✅ 加载解密 metadata: {len(data):,} bytes (magic OK)")
    return bytes(data)


# ==================== APK 重建 ====================

def rebuild_apk(original_apk, new_dex_data, so_path, output_path,
                patched_il2cpp=None, decrypted_metadata=None):
    """
    重建 APK，精确保持每个文件的原始压缩方式。
    这是修复 MT 管理器黑屏问题的关键！

    可选：替换 libil2cpp.so（二进制补丁）和 global-metadata.dat（解密版本）
    """
    with zipfile.ZipFile(original_apk, 'r') as src:
        with zipfile.ZipFile(output_path, 'w') as dst:
            for item in src.infolist():
                # 跳过旧签名
                if item.filename.startswith('META-INF/'):
                    continue

                if item.filename == 'classes.dex':
                    # 替换为修改后的 dex
                    info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                    info.compress_type = item.compress_type
                    info.external_attr = item.external_attr
                    dst.writestr(info, new_dex_data)

                elif item.filename == 'lib/arm64-v8a/libil2cpp.so' and patched_il2cpp:
                    # 替换为补丁后的 libil2cpp.so
                    info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                    info.compress_type = item.compress_type
                    info.external_attr = item.external_attr
                    dst.writestr(info, patched_il2cpp)
                    print(f"  替换 libil2cpp.so ({len(patched_il2cpp):,} bytes, 已补丁)")

                elif (item.filename.endswith('global-metadata.dat') and
                      decrypted_metadata):
                    # 替换为解密的 metadata
                    info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                    info.compress_type = item.compress_type
                    info.external_attr = item.external_attr
                    dst.writestr(info, decrypted_metadata)
                    print(f"  替换 {item.filename} ({len(decrypted_metadata):,} bytes, 已解密)")

                else:
                    # 保持原始压缩方式复制
                    data = src.read(item.filename)
                    info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                    info.compress_type = item.compress_type
                    info.external_attr = item.external_attr
                    dst.writestr(info, data)

            # 添加 libgoldhack.so (使用 DEFLATE，与其他 .so 一致)
            if so_path and os.path.isfile(so_path):
                so_data = open(so_path, 'rb').read()
                so_info = zipfile.ZipInfo("lib/arm64-v8a/libgoldhack.so")
                so_info.compress_type = zipfile.ZIP_DEFLATED
                so_info.external_attr = 0o100755 << 16  # rwxr-xr-x
                dst.writestr(so_info, so_data)
                print(f"  添加 lib/arm64-v8a/libgoldhack.so ({len(so_data):,} bytes)")


def verify_compression(apk_path, reference_apk):
    """验证重建后的 APK 压缩方式与原始一致"""
    with zipfile.ZipFile(reference_apk, 'r') as ref:
        ref_map = {i.filename: i.compress_type for i in ref.infolist()
                   if not i.filename.startswith('META-INF/')}

    with zipfile.ZipFile(apk_path, 'r') as new:
        new_map = {i.filename: i.compress_type for i in new.infolist()}

    mismatch = 0
    for fname, expected in ref_map.items():
        actual = new_map.get(fname)
        if actual is not None and actual != expected:
            ct = {0: 'STORE', 8: 'DEFLATE'}
            print(f"  ⚠ 压缩方式不匹配: {fname}: "
                  f"期望={ct.get(expected, expected)} 实际={ct.get(actual, actual)}")
            mismatch += 1

    return mismatch == 0


# ==================== 主流程 ====================

def main():
    parser = argparse.ArgumentParser(
        description='月圆之夜 APK 重打包工具 - 注入 libgoldhack.so')
    parser.add_argument('--apk', default=DEFAULT_APK,
                        help='原始 APK 路径')
    parser.add_argument('--so', default=DEFAULT_SO,
                        help='libgoldhack.so 路径')
    parser.add_argument('--output', default=DEFAULT_OUTPUT,
                        help='输出 APK 路径')
    parser.add_argument('--no-patch', action='store_true',
                        help='不补丁 libil2cpp.so（保留 MHP 解密）')
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    so_path = os.path.abspath(args.so)
    output_path = os.path.abspath(args.output)

    # 验证输入
    if not os.path.isfile(apk_path):
        print(f"❌ 找不到原始 APK: {apk_path}")
        sys.exit(1)
    if not os.path.isfile(so_path):
        print(f"❌ 找不到 libgoldhack.so: {so_path}")
        print(f"   请先执行 ./build.sh 编译")
        sys.exit(1)
    if not BUILD_TOOLS:
        print("❌ 找不到 Android SDK build-tools")
        print("   请安装 Android SDK 并确保 build-tools 可用")
        sys.exit(1)

    print("=" * 55)
    print("  月圆之夜 APK 重打包工具")
    print("=" * 55)
    print(f"  原始 APK:    {apk_path}")
    print(f"  注入 SO:     {so_path}")
    print(f"  输出 APK:    {output_path}")
    print(f"  Build Tools: {BUILD_TOOLS}")
    print()

    # ---- Step 0: 检查工具 ----
    print("[0/10] 检查工具 ...")
    ensure_tools()
    print("  ✅ 工具就绪")

    # ---- Step 1: 提取原始签名 ----
    print("\n[1/10] 提取原始签名证书 ...")
    cert_hex = extract_original_cert(apk_path)
    if cert_hex:
        print(f"  ✅ 证书提取成功 ({len(cert_hex)} hex chars)")
    else:
        print("  ⚠ 无法提取签名证书，跳过签名伪造")

    # ---- Step 2: 查找注入目标 ----
    print("\n[2/10] 查找注入目标 ...")
    target_class = find_app_class(apk_path)
    if target_class:
        print(f"  Application 类: {target_class}")
    else:
        target_class = find_main_activity(apk_path)
        if target_class:
            print(f"  主 Activity (备选): {target_class}")
        else:
            print("  ❌ 无法找到注入目标类")
            sys.exit(1)

    # ---- Step 3: 反编译 dex ----
    work_dir = tempfile.mkdtemp(prefix="repackage_")
    try:
        print(f"\n[3/10] 反编译 classes.dex ...")
        dex_path = os.path.join(work_dir, "classes.dex")
        smali_dir = os.path.join(work_dir, "smali_out")

        with zipfile.ZipFile(apk_path, 'r') as z:
            with open(dex_path, 'wb') as f:
                f.write(z.read("classes.dex"))

        r = subprocess.run(
            ["java", "-jar", BAKSMALI_JAR, "d", dex_path, "-o", smali_dir],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  ❌ baksmali 失败: {r.stderr}")
            sys.exit(1)

        # 统计
        smali_count = sum(1 for _, _, files in os.walk(smali_dir)
                         for f in files if f.endswith('.smali'))
        print(f"  反编译得到 {smali_count} 个 smali 文件")

        # ---- Step 4: 注入签名伪造 + loadLibrary ----
        print(f"\n[4/10] 注入签名伪造 + System.loadLibrary(\"goldhack\") ...")
        if cert_hex:
            if not copy_sigspoof_smali(smali_dir):
                print("  ⚠ 签名伪造 smali 复制失败，继续无签名伪造")
                cert_hex = None
        if not inject_loadlibrary(smali_dir, target_class, cert_hex=cert_hex):
            sys.exit(1)

        # ---- Step 5: 重编译 dex ----
        print("\n[5/10] 重编译 classes.dex ...")
        new_dex = os.path.join(work_dir, "classes_new.dex")
        r = subprocess.run(
            ["java", "-jar", SMALI_JAR, "a", smali_dir, "-o", new_dex],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  ❌ smali 失败: {r.stderr}")
            sys.exit(1)

        orig_size = os.path.getsize(dex_path)
        new_size = os.path.getsize(new_dex)
        print(f"  原始 dex: {orig_size:,} bytes → 新 dex: {new_size:,} bytes "
              f"(+{new_size - orig_size:,})")

        # ---- Step 6: 补丁 libil2cpp.so ----
        patched_il2cpp = None
        decrypted_metadata = None
        if not args.no_patch:
            print("\n[6/10] 补丁 libil2cpp.so (绕过 MHP 解密+初始化) ...")
            with zipfile.ZipFile(apk_path, 'r') as z:
                orig_il2cpp = z.read('lib/arm64-v8a/libil2cpp.so')
            print(f"  原始 libil2cpp.so: {len(orig_il2cpp):,} bytes")
            patched_il2cpp = patch_libil2cpp(orig_il2cpp)
            if not patched_il2cpp:
                print("  ⚠ 补丁失败，使用原始 libil2cpp.so")

            # ---- Step 7: 加载解密 metadata ----
            print("\n[7/10] 加载解密 global-metadata.dat ...")
            decrypted_metadata = load_decrypted_metadata()
            if not decrypted_metadata:
                print("  ⚠ 无法加载解密 metadata")
                if patched_il2cpp:
                    print("  ❌ 补丁了 libil2cpp.so 但没有解密 metadata，会崩溃！")
                    print("     请提供解密的 global-metadata.dat 或使用 --no-patch")
                    sys.exit(1)
        else:
            print("\n[6/10] 跳过 libil2cpp.so 补丁 (--no-patch)")
            print("[7/10] 跳过 metadata 替换")

        # ---- Step 8: 重建 APK ----
        print("\n[8/10] 重建 APK (保持原始压缩方式) ...")
        unsigned = os.path.join(work_dir, "unsigned.apk")
        new_dex_data = open(new_dex, 'rb').read()
        rebuild_apk(apk_path, new_dex_data, so_path, unsigned,
                    patched_il2cpp=patched_il2cpp,
                    decrypted_metadata=decrypted_metadata)

        # 验证压缩方式
        with zipfile.ZipFile(unsigned, 'r') as z:
            store = sum(1 for i in z.infolist() if i.compress_type == 0)
            deflate = sum(1 for i in z.infolist() if i.compress_type == 8)
        print(f"  文件条目: {store} STORE + {deflate} DEFLATE")

        ok = verify_compression(unsigned, apk_path)
        if ok:
            print("  ✅ 压缩方式验证通过")
        else:
            print("  ⚠ 压缩方式存在差异（但不影响功能）")

        # ---- Step 9: zipalign ----
        print("\n[9/10] 对齐 (zipalign) ...")
        aligned = os.path.join(work_dir, "aligned.apk")
        zipalign = os.path.join(BUILD_TOOLS, "zipalign")
        r = subprocess.run(
            [zipalign, "-f", "-p", "4", unsigned, aligned],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  ❌ zipalign 失败: {r.stderr}")
            sys.exit(1)
        print(f"  ✅ 对齐完成")

        # ---- Step 10: 签名 ----
        print("\n[10/10] 签名 APK ...")
        shutil.copy2(aligned, output_path)
        apksigner = os.path.join(BUILD_TOOLS, "apksigner")
        r = subprocess.run([
            apksigner, "sign",
            "--ks", KEYSTORE,
            "--ks-key-alias", KEY_ALIAS,
            "--ks-pass", f"pass:{KEY_PASS}",
            "--key-pass", f"pass:{KEY_PASS}",
            output_path
        ], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  ❌ 签名失败: {r.stderr}")
            sys.exit(1)

        # 验证签名
        r = subprocess.run(
            [apksigner, "verify", output_path],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            print(f"  ✅ 签名验证通过")
        else:
            print(f"  ⚠ 签名验证: {r.stderr}")

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    # ---- 完成 ----
    size = os.path.getsize(output_path)
    print()
    print("=" * 55)
    print(f"  ✅ 重打包完成!")
    print(f"  输出: {output_path}")
    print(f"  大小: {size:,} bytes ({size / 1024 / 1024:.1f} MB)")
    print("=" * 55)
    print()
    print("安装到模拟器:")
    print(f"  adb install -r \"{output_path}\"")
    print()
    print("安装到真机 (需先卸载原版):")
    print(f"  adb uninstall com.ztgame.yyzy")
    print(f"  adb install \"{output_path}\"")


if __name__ == '__main__':
    main()
