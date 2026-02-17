#!/usr/bin/env python3
"""
inject.py - 通过 Frida 将 libgoldhack.so 注入到游戏进程
支持 attach（游戏已运行）和 spawn（重新启动游戏）两种模式

使用:
  python3 inject.py                  # attach 模式（游戏须已运行）
  python3 inject.py --spawn          # spawn 模式（自动重启游戏）
  python3 inject.py --gold 888888    # 自定义金币值（需重新编译）
"""

import frida
import sys
import time
import subprocess
import argparse
import os

PACKAGE = "com.ztgame.yyzy"
SO_NAME = "libgoldhack.so"
REMOTE_PATH = f"/data/local/tmp/{SO_NAME}"

def push_so():
    """推送 .so 到设备"""
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), SO_NAME)
    if not os.path.exists(local_path):
        print(f"[-] {local_path} not found! Run build.sh first.")
        return False
    
    print(f"[*] Pushing {SO_NAME} to device...")
    ret = subprocess.run(["adb", "push", local_path, REMOTE_PATH], capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"[-] adb push failed: {ret.stderr}")
        return False
    
    # 设置权限
    subprocess.run(["adb", "shell", f"chmod 755 {REMOTE_PATH}"], capture_output=True)
    print(f"[+] Pushed to {REMOTE_PATH}")
    return True

def inject_attach(device, wait_time=20):
    """attach 模式: 附加到运行中的进程"""
    print(f"[*] Looking for {PACKAGE}...")
    
    try:
        session = device.attach(PACKAGE)
    except frida.ProcessNotFoundError:
        # 尝试中文名
        try:
            session = device.attach("月圆之夜")
        except Exception as e:
            print(f"[-] Cannot find game process: {e}")
            return False
    except frida.TransportError as e:
        print(f"[-] Attach failed (anti-debug?): {e}")
        print("[*] Try --spawn mode instead")
        return False

    print(f"[*] Attached to process")
    
    # 通过 Frida 加载 .so
    script = session.create_script(f'''
        var mod = Module.load("{REMOTE_PATH}");
        send({{type: "loaded", name: mod.name, base: mod.base.toString()}});
    ''')
    
    result = {}
    def on_msg(msg, data):
        if msg['type'] == 'send':
            result.update(msg['payload'])
    
    script.on('message', on_msg)
    script.load()
    time.sleep(2)
    
    if result.get('type') == 'loaded':
        print(f"[+] {SO_NAME} loaded at {result.get('base')}")
    
    print(f"[*] Waiting {wait_time}s for hack to complete...")
    time.sleep(wait_time)
    
    try:
        script.unload()
        session.detach()
    except:
        pass
    
    return True

def inject_spawn(device, wait_time=30):
    """spawn 模式: 重启游戏并注入"""
    print(f"[*] Killing {PACKAGE}...")
    subprocess.run(["adb", "shell", f"am force-stop {PACKAGE}"], capture_output=True)
    time.sleep(2)
    
    print(f"[*] Spawning {PACKAGE}...")
    pid = device.spawn([PACKAGE])
    print(f"[*] PID: {pid}")
    
    session = device.attach(pid)
    
    # 加载 .so (在 resume 之前)
    script = session.create_script(f'''
        // .so 的 constructor 中会 sleep 等待游戏加载，所以先加载没问题
        var mod = Module.load("{REMOTE_PATH}");
        send({{type: "loaded", name: mod.name, base: mod.base.toString()}});
    ''')
    
    result = {}
    def on_msg(msg, data):
        if msg['type'] == 'send':
            result.update(msg['payload'])
        elif msg['type'] == 'error':
            print(f"[-] Error: {msg.get('stack', '')[:200]}")
    
    script.on('message', on_msg)
    script.load()
    time.sleep(1)
    
    if result.get('type') == 'loaded':
        print(f"[+] {SO_NAME} loaded at {result.get('base')}")
    
    device.resume(pid)
    print(f"[*] Game resumed, waiting {wait_time}s for hack to complete...")
    print(f"[*] Watch logcat: adb logcat -s GoldHack")
    time.sleep(wait_time)
    
    try:
        script.unload()
        session.detach()
    except:
        pass
    
    return True

def main():
    parser = argparse.ArgumentParser(description="月圆之夜金币修改器注入工具")
    parser.add_argument("--spawn", action="store_true", help="重启游戏并注入（默认attach到已运行的进程）")
    parser.add_argument("--wait", type=int, default=30, help="等待时间(秒)")
    parser.add_argument("--skip-push", action="store_true", help="跳过推送.so步骤")
    args = parser.parse_args()

    # 推送 .so
    if not args.skip_push:
        if not push_so():
            return

    # 连接设备
    try:
        device = frida.get_usb_device(timeout=5)
        print(f"[*] Device: {device.name}")
    except Exception as e:
        print(f"[-] No USB device found: {e}")
        return

    # 注入
    if args.spawn:
        success = inject_spawn(device, args.wait)
    else:
        success = inject_attach(device, args.wait)

    if success:
        print("\n[*] Done! Check logcat for results:")
        print("    adb logcat -s GoldHack")
    else:
        print("\n[-] Injection failed")

if __name__ == "__main__":
    main()
