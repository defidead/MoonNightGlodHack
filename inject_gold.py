#!/usr/bin/env python3
"""
inject_gold.py - 月圆之夜金币修改器 + 探索技能解锁
使用 Frida 在目标进程中执行修改逻辑
无需 Android NDK，支持任意设备

功能:
  1. 修改金币为目标值
  2. 清除所有探索技能 CD，使其始终可用

使用:
  python3 inject_gold.py                     # 默认 99999 金币 (spawn 模式)
  python3 inject_gold.py --gold 888888       # 自定义金币值
  python3 inject_gold.py --attach            # attach 到已运行的游戏
  python3 inject_gold.py --gold 888888 --attach
"""

import frida
import sys
import time
import subprocess
import argparse
import os

PACKAGE = "com.ztgame.yyzy"

# ================ Frida 注入脚本 ================
# 包含完整的 API 发现 + 实例扫描 + 金币修改逻辑
def make_script(target_gold):
    return r"""
"use strict";

var TARGET_GOLD = """ + str(target_gold) + r""";

// ============ 等待游戏加载后执行 ============
function waitForModule(name, callback) {
    var mod = Process.findModuleByName(name);
    if (mod) {
        callback(mod);
        return;
    }
    var timer = setInterval(function() {
        mod = Process.findModuleByName(name);
        if (mod) {
            clearInterval(timer);
            callback(mod);
        }
    }, 500);
}

setTimeout(function() {
    waitForModule("libil2cpp.so", function(il2cppModule) {
        send({t:"log", m:"libil2cpp.so found: base=" + il2cppModule.base + " size=" + il2cppModule.size});

        // 额外等待确保 il2cpp 初始化完成
        setTimeout(function() {
            try {
                doHack(il2cppModule);
            } catch(e) {
                send({t:"error", m:"doHack exception: " + e.toString()});
            }
        }, 8000);
    });
}, 3000);

function doHack(il2cppModule) {
    var base = il2cppModule.base;
    
    // ============ 需要发现的 API 列表 ============
    var apiNames = [
        "il2cpp_domain_get",
        "il2cpp_thread_attach",
        "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image",
        "il2cpp_image_get_name",
        "il2cpp_class_from_name",
    ];
    
    var apiFuncs = {};
    
    // ============ 方法1: 尝试 Module.findExportByName ============
    var found = 0;
    apiNames.forEach(function(name) {
        var addr = Module.findExportByName("libil2cpp.so", name);
        if (addr) {
            apiFuncs[name] = addr;
            found++;
        }
    });
    
    if (found === apiNames.length) {
        send({t:"log", m:"All APIs found via exports"});
    } else {
        send({t:"log", m:"Exports: " + found + "/" + apiNames.length + ", falling back to memory scan..."});
        
        // ============ 方法2: 内存扫描发现 API ============
        // 步骤1: 扫描所有可读区域查找 API 字符串
        var stringAddrs = {}; // api_name -> [addresses]
        
        Process.enumerateRanges('r--').forEach(function(range) {
            if (range.size < 32 || range.size > 200*1024*1024) return;
            if (range.file && range.file.path && range.file.path.indexOf('/dev/') !== -1) return;
            
            apiNames.forEach(function(name) {
                if (apiFuncs[name]) return; // 已通过 export 找到
                try {
                    var results = Memory.scanSync(range.base, range.size, stringToPattern(name));
                    results.forEach(function(match) {
                        // 验证是完整字符串 (前一个字节不是字母，后一个字节是 \0)
                        try {
                            var nextByte = match.address.add(name.length).readU8();
                            if (nextByte !== 0) return;
                        } catch(e) { return; }
                        
                        if (!stringAddrs[name]) stringAddrs[name] = [];
                        stringAddrs[name].push(match.address);
                    });
                } catch(e) {}
            });
        });
        
        // 步骤2: 在 rw- 匿名区域查找 {string_ptr, func_ptr} 配对
        var ptrSize = Process.pointerSize;
        
        Process.enumerateRanges('rw-').forEach(function(range) {
            if (range.size < 16 || range.size > 200*1024*1024) return;
            if (range.file && range.file.path && range.file.path.length > 0) return; // 匿名区域
            
            apiNames.forEach(function(name) {
                if (apiFuncs[name]) return;
                var addrs = stringAddrs[name];
                if (!addrs || addrs.length === 0) return;
                
                addrs.forEach(function(strAddr) {
                    if (apiFuncs[name]) return;
                    
                    // 搜索指向这个字符串的指针
                    var strAddrHex = strAddr.toString(16).replace("0x","").padStart(16,"0");
                    var pattern = "";
                    for (var i = strAddrHex.length - 2; i >= 0; i -= 2) {
                        if (pattern.length > 0) pattern += " ";
                        pattern += strAddrHex.substr(i, 2);
                    }
                    
                    try {
                        var matches = Memory.scanSync(range.base, range.size, pattern);
                        matches.forEach(function(ptrMatch) {
                            if (apiFuncs[name]) return;
                            
                            // 下一个指针应该是函数地址
                            try {
                                var funcPtr = ptrMatch.address.add(ptrSize).readPointer();
                                if (funcPtr.isNull()) return;
                                
                                // 验证函数指针指向可执行区域
                                var funcAddr = parseInt(funcPtr.toString(16), 16);
                                if (funcAddr < 0x10000) return;
                                
                                apiFuncs[name] = funcPtr;
                                send({t:"log", m:"[scan] " + name + " @ " + funcPtr});
                            } catch(e) {}
                        });
                    } catch(e) {}
                });
            });
        });
    }
    
    // ============ 验证所有 API ============
    var missing = [];
    apiNames.forEach(function(name) {
        if (!apiFuncs[name]) missing.push(name);
    });
    
    if (missing.length > 0) {
        send({t:"error", m:"Missing APIs: " + missing.join(", ")});
        return;
    }
    send({t:"log", m:"All " + apiNames.length + " APIs resolved"});
    
    // ============ 创建 NativeFunction 包装器 ============
    var api = {
        domain_get:            new NativeFunction(apiFuncs["il2cpp_domain_get"], 'pointer', []),
        thread_attach:         new NativeFunction(apiFuncs["il2cpp_thread_attach"], 'pointer', ['pointer']),
        domain_get_assemblies: new NativeFunction(apiFuncs["il2cpp_domain_get_assemblies"], 'pointer', ['pointer', 'pointer']),
        assembly_get_image:    new NativeFunction(apiFuncs["il2cpp_assembly_get_image"], 'pointer', ['pointer']),
        image_get_name:        new NativeFunction(apiFuncs["il2cpp_image_get_name"], 'pointer', ['pointer']),
        class_from_name:       new NativeFunction(apiFuncs["il2cpp_class_from_name"], 'pointer', ['pointer', 'pointer', 'pointer']),
    };
    
    // ============ 初始化 il2cpp ============
    var domain = api.domain_get();
    if (domain.isNull()) { send({t:"error",m:"domain is NULL"}); return; }
    api.thread_attach(domain);
    send({t:"log",m:"Domain: " + domain});
    
    // ============ 找到 Assembly-CSharp.dll ============
    var sizePtr = Memory.alloc(4);
    var assemblies = api.domain_get_assemblies(domain, sizePtr);
    var asmCount = sizePtr.readU32();
    send({t:"log",m:"Assemblies: " + asmCount});
    
    var csharpImage = null;
    for (var i = 0; i < asmCount; i++) {
        var asm = assemblies.add(i * Process.pointerSize).readPointer();
        var img = api.assembly_get_image(asm);
        if (img.isNull()) continue;
        var name = api.image_get_name(img).readUtf8String();
        if (name === "Assembly-CSharp.dll") {
            csharpImage = img;
            break;
        }
    }
    
    if (!csharpImage) { send({t:"error",m:"Assembly-CSharp.dll not found"}); return; }
    send({t:"log",m:"Assembly-CSharp.dll: " + csharpImage});
    
    // ============ 找到 RoleInfo 类 ============
    var roleInfoClass = api.class_from_name(
        csharpImage,
        Memory.allocUtf8String(""),
        Memory.allocUtf8String("RoleInfo")
    );
    
    if (!roleInfoClass || roleInfoClass.isNull()) { send({t:"error",m:"RoleInfo class not found"}); return; }
    send({t:"log",m:"RoleInfo klass: " + roleInfoClass});
    
    // ============ 扫描并修改 RoleInfo 实例 ============
    var klassPattern = ptrToLePattern(roleInfoClass);
    send({t:"log",m:"Scanning heap for RoleInfo instances (pattern: " + klassPattern + ")..."});
    
    var modified = 0;
    var candidates = 0;
    
    Process.enumerateRanges('rw-').forEach(function(range) {
        if (range.size < 0x100 || range.size > 200*1024*1024) return;
        if (range.file && range.file.path &&
            (range.file.path.indexOf('.so') !== -1 || range.file.path.indexOf('/dev/') !== -1)) return;
        
        try {
            Memory.scanSync(range.base, range.size, klassPattern).forEach(function(match) {
                var addr = match.address;
                // 8字节对齐检查
                if (parseInt(addr.toString(16), 16) % 8 !== 0) return;
                
                try {
                    // 验证 monitor (offset +8)
                    var monitor = addr.add(8).readPointer();
                    var monVal = parseInt(monitor.toString(16), 16);
                    if (monVal !== 0 && monVal < 0x10000) return;
                    
                    // 验证 roleId (offset 0x10): 0-200
                    var roleId = addr.add(0x10).readS32();
                    if (roleId < 0 || roleId > 200) return;
                    
                    // 验证 maxHp (offset 0x14): 0-99999
                    var maxHp = addr.add(0x14).readS32();
                    if (maxHp < 0 || maxHp > 99999) return;
                    
                    // 验证 curHp (offset 0x18): 0-99999
                    var curHp = addr.add(0x18).readS32();
                    if (curHp < 0 || curHp > 99999) return;
                    
                    // 验证 level (offset 0x24): 0-100
                    var level = addr.add(0x24).readS32();
                    if (level < 0 || level > 100) return;
                    
                    candidates++;
                    var oldGold = addr.add(0x2c).readS32();
                    
                    send({t:"log", m:"  RoleInfo @ " + addr + ": roleId=" + roleId +
                          " level=" + level + " HP=" + curHp + "/" + maxHp +
                          " gold=" + oldGold});
                    
                    // 修改金币!
                    addr.add(0x2c).writeS32(TARGET_GOLD);
                    modified++;
                    
                    send({t:"gold", m:"  ✅ Gold: " + oldGold + " -> " + TARGET_GOLD,
                          old: oldGold, new_val: TARGET_GOLD, addr: addr.toString()});
                    
                    // ========= 探索技能 CD 清零 =========
                    // RoleInfo.[0x80] UserSkillState dungeonSkill (对象指针)
                    // RoleInfo.[0x88] List<UserSkillState> skills
                    // UserSkillState.[0x10] Int32 skillId
                    // UserSkillState.[0x14] Int32 cd
                    try {
                        var dungeonSkill = addr.add(0x80).readPointer();
                        if (!dungeonSkill.isNull() && parseInt(dungeonSkill.toString(16), 16) > 0x10000) {
                            var dSkillId = dungeonSkill.add(0x10).readS32();
                            var dCd = dungeonSkill.add(0x14).readS32();
                            send({t:"log", m:"  DungeonSkill: id=" + dSkillId + " cd=" + dCd});
                            if (dCd > 0) {
                                dungeonSkill.add(0x14).writeS32(0);
                                send({t:"log", m:"  ✅ DungeonSkill CD: " + dCd + " -> 0"});
                            }
                        }
                    } catch(e) { send({t:"log", m:"  [warn] dungeonSkill access error: " + e}); }

                    // 遍历 skills 列表，清除所有技能 CD
                    try {
                        var skillsList = addr.add(0x88).readPointer();
                        if (!skillsList.isNull() && parseInt(skillsList.toString(16), 16) > 0x10000) {
                            // List<T> 内部: [klass(8)] [monitor(8)] [_items(8)] [_size(4)]
                            var items = skillsList.add(0x10).readPointer(); // _items (Array)
                            var size = skillsList.add(0x18).readS32();      // _size
                            send({t:"log", m:"  Skills list size: " + size});
                            
                            if (size > 0 && size < 100 && !items.isNull()) {
                                // Array 内部: [klass(8)] [monitor(8)] [max_length(8)] [elements...]
                                var elemBase = items.add(0x20); // 64位: 8+8+8 = 0x18, 但 il2cpp Array header 通常 0x20
                                for (var si = 0; si < size; si++) {
                                    var skillObj = elemBase.add(si * Process.pointerSize).readPointer();
                                    if (skillObj.isNull()) continue;
                                    var sId = skillObj.add(0x10).readS32();
                                    var sCd = skillObj.add(0x14).readS32();
                                    if (sCd > 0) {
                                        skillObj.add(0x14).writeS32(0);
                                        send({t:"log", m:"  ✅ Skill[" + si + "] id=" + sId + " CD: " + sCd + " -> 0"});
                                    } else {
                                        send({t:"log", m:"  Skill[" + si + "] id=" + sId + " CD=" + sCd + " (already 0)"});
                                    }
                                }
                            }
                        }
                    } catch(e) { send({t:"log", m:"  [warn] skills list access error: " + e}); }
                    // ========= 探索技能 CD 清零 END =========
                    
                } catch(e) {}
            });
        } catch(e) {}
    });
    
    send({t:"log", m:"Scan complete: " + candidates + " valid candidates, " + modified + " modified"});
    
    if (modified > 0) {
        send({t:"success", m:"Modified " + modified + " RoleInfo instance(s)", count: modified});
    } else {
        send({t:"warning", m:"No valid RoleInfo instances found. Are you in a game session?"});
    }
    
    send({t:"done"});
}

// ============ 辅助函数 ============
function stringToPattern(str) {
    var hex = "";
    for (var i = 0; i < str.length; i++) {
        if (hex.length > 0) hex += " ";
        hex += ("0" + str.charCodeAt(i).toString(16)).slice(-2);
    }
    // 加上 \0 终止符
    hex += " 00";
    return hex;
}

function ptrToLePattern(ptr) {
    var hex = ptr.toString(16).replace("0x","").padStart(Process.pointerSize * 2, "0");
    var parts = [];
    for (var i = hex.length - 2; i >= 0; i -= 2) {
        parts.push(hex.substr(i, 2));
    }
    return parts.join(" ");
}
"""

done = False

def on_message(message, data):
    global done
    if message['type'] == 'send':
        p = message['payload']
        t = p.get('t', '')
        m = p.get('m', '')
        
        if t == 'log':
            print(f"  [*] {m}")
        elif t == 'error':
            print(f"  [-] {m}")
        elif t == 'gold':
            print(f"  💰 {m}")
        elif t == 'success':
            print(f"\n  🎉 {m}")
        elif t == 'warning':
            print(f"\n  ⚠️  {m}")
        elif t == 'done':
            done = True
    elif message['type'] == 'error':
        print(f"  [ERR] {message.get('stack', str(message))[:300]}")


def main():
    global done
    
    parser = argparse.ArgumentParser(description="月圆之夜 金币修改器")
    parser.add_argument("--gold", type=int, default=99999, help="目标金币值 (默认 99999)")
    parser.add_argument("--attach", action="store_true", help="attach 到已运行的游戏 (默认 spawn 模式)")
    parser.add_argument("--wait", type=int, default=15, help="游戏加载等待时间(秒)")
    args = parser.parse_args()
    
    print("="*50)
    print(f"  🌕 月圆之夜 - 金币修改器")
    print(f"  目标金币: {args.gold}")
    print(f"  模式: {'attach' if args.attach else 'spawn'}")
    print("="*50)
    
    try:
        device = frida.get_usb_device(timeout=5)
        print(f"\n[*] Device: {device.name}")
    except Exception as e:
        print(f"[-] No USB device: {e}")
        return
    
    script_code = make_script(args.gold)
    
    if args.attach:
        # Attach 模式
        print(f"[*] Attaching to {PACKAGE}...")
        try:
            session = device.attach(PACKAGE)
        except frida.ProcessNotFoundError:
            try:
                session = device.attach("月圆之夜")
            except:
                print(f"[-] Game not running. Use spawn mode (without --attach)")
                return
        except Exception as e:
            print(f"[-] Attach failed: {e}")
            return
        
        print("[*] Attached!")
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
    else:
        # Spawn 模式
        print(f"[*] Stopping {PACKAGE}...")
        subprocess.run(["adb", "shell", f"am force-stop {PACKAGE}"], capture_output=True)
        time.sleep(2)
        
        print(f"[*] Spawning {PACKAGE}...")
        pid = device.spawn([PACKAGE])
        print(f"[*] PID: {pid}")
        
        session = device.attach(pid)
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        device.resume(pid)
        print("[*] Game resumed")
    
    print(f"[*] Waiting for hack to complete...\n")
    
    for _ in range(60):
        if done:
            break
        time.sleep(1)
    
    time.sleep(2)
    try:
        script.unload()
        session.detach()
    except:
        pass
    
    print("\n[*] Done!")


if __name__ == "__main__":
    main()
