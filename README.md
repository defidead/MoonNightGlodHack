# 月圆之夜 Android 修改器

针对 **月圆之夜 v1.6.28**（`com.ztgame.yyzy`）的内存修改工具。支持修改金币、重置技能 CD，带游戏内悬浮菜单。

游戏使用 Unity il2cpp + HybridCLR，并有 MHP v3.5.0 保护（剥离 il2cpp API 符号 + hook dlsym）。

## 两种方案

| 方案 | 分支 | 需要 Root | 说明 |
|------|------|-----------|------|
| **Frida 注入** | `main` | ✅ 需要 | 通过 Frida 将 .so 注入到运行中的游戏进程 |
| **APK 重打包** | `repackage` | ❌ 不需要 | 修改 APK 内嵌 .so，安装即用 |

---

## 方案一：Frida 注入（需要 Root）

自行研究如何注入 so 文件，写的 py 为基于 frida 的注入，没有进行最终验证，项目最终验证于 xiaomipad6 android15 版本，模拟器为 mumu（mac），frida 版本为 frida-server-16.5.9-android-arm64
```
uname -a
Linux localhost 5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284 #1 SMP PREEMPT Tue Oct 21 03:03:12 UTC 2025 aarch64 Toybox
```

## 方案二：APK 重打包（无需 Root）⭐

### 原理

将 `libgoldhack.so` 直接打包进 APK，通过 smali 注入在 `Application.attachBaseContext()` 中 `System.loadLibrary("goldhack")`，游戏启动时自动加载。

### 需要绕过的保护

游戏有 **4 层保护**，重打包方案全部绕过：

| # | 保护 | 绕过方式 |
|---|------|----------|
| 1 | **APK 签名校验** | Java 层 `PackageManager` Proxy hook（`SigSpoof.java`），返回原始签名证书 |
| 2 | **MHP 元数据解密** | 二进制补丁 libil2cpp.so（Patch #1），NOP 掉解密回调，替换为预解密的 `global-metadata.dat` |
| 3 | **MHP 初始化回调** | 二进制补丁（Patch #2A/2B/2C），通过 code cave 直接计算 CodeReg/MetaReg/Extra 地址 |
| 4 | **SecSDK 反篡改自杀** | `libgoldhack.so` 中 inline hook libc `kill()`，拦截 `kill(getpid(), SIGKILL)` |

### MHP 元数据头部处理

MHP v3.5.0 不仅解密 metadata 数据，还会创建**独立的头部缓冲区**，重排所有字段偏移（SIZE 相同，OFFSET 不同）。重打包时需要用 Frida 从原版游戏运行时捕获 256 字节 MHP 头部（`mhp_header.bin`），替换解密 metadata 的前 256 字节。

### HybridCLR 动态加载

游戏使用 HybridCLR 热更新框架，`Assembly-CSharp.dll` 不在 il2cpp 的静态 87 个 assembly 中，而是在运行时动态加载（最终共 101 个 assembly）。`libgoldhack.so` 通过轮询等待（最多 60 秒）直到 HybridCLR 加载完成。

### 使用步骤

```bash
# 1. 从 GitHub Actions 下载最新编译的 libgoldhack.so，放到 gold_hack/ 目录

# 2. 准备前置文件（只需一次）
#    - 月圆之夜_1.6.28.apk（原版 APK）
#    - decrypted_output/global-metadata.dat（预解密的元数据，通过 Frida 从原版运行时 dump）
#    - decrypted_output/mhp_header.bin（256 字节 MHP 头部，通过 dump_mhp_header_py.py 捕获）

# 3. 运行重打包
cd gold_hack
python3 repackage.py

# 4. 安装（模拟器可直接覆盖，真机需先卸载原版）
adb install -r 月圆之夜_modded.apk
```

### 二进制补丁详情

所有补丁应用于 `libil2cpp.so`（73.6 MB，ARM64）：

| 补丁 | 偏移 | 大小 | 说明 |
|------|------|------|------|
| Patch #1 | `0xF7E300` | 20B | `STUR X8, [X21, #-0x60]` + 4×NOP — 跳过 MHP 解密回调 |
| Patch #2A | `0xF74C90` | 16B | 3×NOP + `BL sub_F848F4` — 绕过 MHP init callback 调用点 |
| Patch #2B | `0xF848F4` | 4B | 修改 `sub_F848F4` 的第一条 BL 跳转到 code cave |
| Patch #2C | `0xCDD088` | 28B | Code cave — ADRP/ADD 计算 MetaReg/CodeReg/Extra 注册结构地址 |

### Anti-Kill Hook

`libsecsdk.so` 在游戏启动约 14 秒后检测 APK 篡改并调用 `kill(getpid(), SIGKILL)` 自杀。`libgoldhack.so` 在构造函数中第一时间 inline hook libc 的 `kill()` 函数：

```
kill() 入口 → LDR X16, [PC, #8]; BR X16 → hook_kill_func()
  if (sig == SIGKILL && pid == getpid()) → return 0  // 阻止自杀
  else → syscall(__NR_kill, pid, sig)                 // 正常转发
```

---

## 文件说明

### 核心

| 文件 | 说明 |
|------|------|
| `gold_hack.c` | 主体 C 代码，编译为 `libgoldhack.so`。包含 il2cpp API 内存扫描（绕 MHP）、RoleInfo 实例查找、金币修改、技能 CD 重置、API 缓存、JNI 悬浮菜单加载、kill() anti-kill hook |
| `OverlayMenu.java` | 游戏内悬浮菜单 UI（纯代码布局），编译为 DEX 嵌入 .so，通过 JNI 回调 native 方法 |
| `repackage.py` | APK 重打包工具（10 步流水线）：提取签名→反编译→smali 注入→重编译→补丁 libil2cpp.so→替换 metadata→重建 APK→对齐→签名 |
| `inject.py` | 通过 Frida 将 `libgoldhack.so` 注入游戏进程（支持 spawn/attach） |

### 替代方案（纯 Frida，无需编译）

| 文件 | 说明 |
|------|------|
| `inject_gold.py` | 纯 Python+Frida 方案，内嵌完整的 JS 注入脚本，一键修改金币+重置技能 |

### 构建

| 文件 | 说明 |
|------|------|
| `build.sh` | 本地编译脚本（需要 Android NDK） |
| `.github/workflows/build.yml` | GitHub Actions CI：Java→DEX→xxd→C header→NDK 编译，自动产出 arm64 + armv7a 的 .so |

## RoleInfo 关键字段偏移

从 `dump.txt` 中 `RoleInfo` 类提取（`Assembly-CSharp.dll`，49 个字段）：

```
0x10  roleId          0x14  modeId          0x18  maxHp
0x1c  curHp           0x20  curMp           0x24  curexp
0x28  curvessel       0x2c  curgold ★       0x30  handcards
0x34  level           0x38  curAction       0x3c  area
0x40  reputation      0x80  dungeonSkill    0x88  skills
0xf0  RecordGoldByFightGet
```

## MHP 保护绕过

MHP v3.5.0（`libc_llite.so`）的保护措施：
- 剥离 `libil2cpp.so` 所有 API 导出符号
- Hook `dlsym` 返回 NULL
- 真实函数在 trampoline 区域（非 libil2cpp.so 地址空间）

绕过方式：
1. 在 libil2cpp.so 只读段搜索 `"il2cpp_"` 字符串
2. 在 rw- 匿名段搜索指向这些字符串的指针（pair table，结构 `{name_ptr, ?, func_ptr}`，间距 0x18）
3. 取 pair 中偏移 +2 的指针即为 trampoline 函数地址（需验证 ARM64 4 字节对齐 + 可执行区域）
