# 月圆之夜 手机版 修改器

针对 **月圆之夜 v1.6.28**（`com.ztgame.yyzy`）的内存修改工具。支持修改金币、重置技能 CD，带游戏内悬浮菜单。

游戏使用 Unity il2cpp + HybridCLR，并有 MHP v3.5.0 保护（剥离 il2cpp API 符号 + hook dlsym）。

## 使用
自行研究如何注入so文件，写的py为基于frida的注入，没有进行最终验证，项目最终验证于xiaomipad6 android15版本,模拟器为mumu（mac），frida版本为frida-server-16.5.9-android-arm64
```
uname -a
Linux localhost 5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284 #1 SMP PREEMPT Tue Oct 21 03:03:12 UTC 2025 aarch64 Toybox
```

## 文件说明

### 核心

| 文件 | 说明 |
|------|------|
| `gold_hack.c` | 主体 C 代码，编译为 `libgoldhack.so` 注入游戏进程。包含 il2cpp API 内存扫描（绕 MHP）、RoleInfo 实例查找、金币修改、技能 CD 重置、API 缓存、JNI 悬浮菜单加载 |
| `OverlayMenu.java` | 游戏内悬浮菜单 UI（纯代码布局），编译为 DEX 嵌入 .so，通过 JNI 回调 native 方法 |
| `inject.py` | 通过 Frida 将 `libgoldhack.so` 注入游戏进程（支持 spawn/attach） |

### 替代方案（纯 Frida，无需编译）

| 文件 | 说明 |
|------|------|
| `inject_gold.py` | 纯 Python+Frida 方案，内嵌完整的 JS 注入脚本，一键修改金币+重置技能 |

### 逆向分析数据

| 文件 | 说明 |
|------|------|
| `dump.js` | Frida 脚本，通过 il2cpp 运行时反射 API 枚举所有类的字段偏移和方法（需要 MHP API 偏移） |
| `dump.txt` | `dump.js` 的输出结果（26 万行），包含游戏全部 25,579 个类的字段/方法信息。**`RoleInfo.curgold` 偏移 `0x2c` 就是从这里确认的** |

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
