#!/usr/bin/env python3
"""
control_panel.py - 月圆之夜 悬浮窗控制面板
在游戏内显示悬浮窗，可随时修改金币、重置技能CD

使用:
  python3 control_panel.py                 # spawn 模式启动游戏
  python3 control_panel.py --attach        # attach 到已运行的游戏
"""

import frida
import sys
import time
import subprocess
import argparse
import threading

PACKAGE = "com.ztgame.yyzy"

# ================ Frida 注入脚本 ================
FRIDA_SCRIPT = r"""
"use strict";

// ============ 全局状态 ============
var g_api = null;          // il2cpp API 函数
var g_csharpImage = null;  // Assembly-CSharp image
var g_roleInfoClass = null;
var g_overlayCreated = false;

// ============ 等待模块加载 ============
function waitForModule(name, callback) {
    var mod = Process.findModuleByName(name);
    if (mod) { callback(mod); return; }
    var timer = setInterval(function() {
        mod = Process.findModuleByName(name);
        if (mod) { clearInterval(timer); callback(mod); }
    }, 500);
}

setTimeout(function() {
    waitForModule("libil2cpp.so", function(il2cppModule) {
        send({t:"log", m:"libil2cpp.so loaded: " + il2cppModule.base});
        setTimeout(function() {
            try {
                initApis(il2cppModule);
                if (g_api) {
                    createOverlay();
                }
            } catch(e) {
                send({t:"error", m:"Init failed: " + e});
            }
        }, 8000);
    });
}, 3000);

// ============ 发现并缓存 il2cpp API ============
function initApis(il2cppModule) {
    var apiNames = [
        "il2cpp_domain_get",
        "il2cpp_thread_attach",
        "il2cpp_domain_get_assemblies",
        "il2cpp_assembly_get_image",
        "il2cpp_image_get_name",
        "il2cpp_class_from_name",
    ];
    
    var apiFuncs = {};
    var found = 0;
    
    // 方法1: exports
    apiNames.forEach(function(name) {
        var addr = Module.findExportByName("libil2cpp.so", name);
        if (addr) { apiFuncs[name] = addr; found++; }
    });
    
    if (found < apiNames.length) {
        send({t:"log", m:"Exports: " + found + "/" + apiNames.length + ", scanning memory..."});
        
        // 方法2: 内存扫描
        var stringAddrs = {};
        Process.enumerateRanges('r--').forEach(function(range) {
            if (range.size < 32 || range.size > 200*1024*1024) return;
            if (range.file && range.file.path && range.file.path.indexOf('/dev/') !== -1) return;
            apiNames.forEach(function(name) {
                if (apiFuncs[name]) return;
                try {
                    Memory.scanSync(range.base, range.size, stringToPattern(name)).forEach(function(match) {
                        try {
                            if (match.address.add(name.length).readU8() !== 0) return;
                        } catch(e) { return; }
                        if (!stringAddrs[name]) stringAddrs[name] = [];
                        stringAddrs[name].push(match.address);
                    });
                } catch(e) {}
            });
        });
        
        var ptrSize = Process.pointerSize;
        Process.enumerateRanges('rw-').forEach(function(range) {
            if (range.size < 16 || range.size > 200*1024*1024) return;
            if (range.file && range.file.path && range.file.path.length > 0) return;
            apiNames.forEach(function(name) {
                if (apiFuncs[name]) return;
                var addrs = stringAddrs[name];
                if (!addrs) return;
                addrs.forEach(function(strAddr) {
                    if (apiFuncs[name]) return;
                    var hex = strAddr.toString(16).replace("0x","").padStart(16,"0");
                    var pattern = "";
                    for (var i = hex.length - 2; i >= 0; i -= 2) {
                        if (pattern.length > 0) pattern += " ";
                        pattern += hex.substr(i, 2);
                    }
                    try {
                        Memory.scanSync(range.base, range.size, pattern).forEach(function(m) {
                            if (apiFuncs[name]) return;
                            try {
                                var fp = m.address.add(ptrSize).readPointer();
                                if (!fp.isNull() && parseInt(fp.toString(16),16) > 0x10000) {
                                    apiFuncs[name] = fp;
                                    send({t:"log", m:"[scan] " + name + " @ " + fp});
                                }
                            } catch(e) {}
                        });
                    } catch(e) {}
                });
            });
        });
    }
    
    var missing = [];
    apiNames.forEach(function(n) { if (!apiFuncs[n]) missing.push(n); });
    if (missing.length > 0) {
        send({t:"error", m:"Missing APIs: " + missing.join(", ")});
        return;
    }
    
    g_api = {
        domain_get:            new NativeFunction(apiFuncs["il2cpp_domain_get"], 'pointer', []),
        thread_attach:         new NativeFunction(apiFuncs["il2cpp_thread_attach"], 'pointer', ['pointer']),
        domain_get_assemblies: new NativeFunction(apiFuncs["il2cpp_domain_get_assemblies"], 'pointer', ['pointer', 'pointer']),
        assembly_get_image:    new NativeFunction(apiFuncs["il2cpp_assembly_get_image"], 'pointer', ['pointer']),
        image_get_name:        new NativeFunction(apiFuncs["il2cpp_image_get_name"], 'pointer', ['pointer']),
        class_from_name:       new NativeFunction(apiFuncs["il2cpp_class_from_name"], 'pointer', ['pointer', 'pointer', 'pointer']),
    };
    
    // 初始化 domain
    var domain = g_api.domain_get();
    if (domain.isNull()) { send({t:"error",m:"domain NULL"}); g_api = null; return; }
    g_api.thread_attach(domain);
    
    var sizePtr = Memory.alloc(4);
    var assemblies = g_api.domain_get_assemblies(domain, sizePtr);
    var asmCount = sizePtr.readU32();
    
    for (var i = 0; i < asmCount; i++) {
        var asm_ = assemblies.add(i * Process.pointerSize).readPointer();
        var img = g_api.assembly_get_image(asm_);
        if (img.isNull()) continue;
        var name = g_api.image_get_name(img).readUtf8String();
        if (name === "Assembly-CSharp.dll") { g_csharpImage = img; break; }
    }
    if (!g_csharpImage) { send({t:"error",m:"Assembly-CSharp.dll not found"}); g_api = null; return; }
    
    g_roleInfoClass = g_api.class_from_name(g_csharpImage, Memory.allocUtf8String(""), Memory.allocUtf8String("RoleInfo"));
    if (!g_roleInfoClass || g_roleInfoClass.isNull()) {
        send({t:"error",m:"RoleInfo class not found"});
        g_api = null; return;
    }
    
    send({t:"log", m:"✅ All APIs ready, RoleInfo klass: " + g_roleInfoClass});
}

// ============ 核心修改函数 ============
function doModifyGold(amount) {
    if (!g_api) return "APIs not ready";
    var klassPattern = ptrToLePattern(g_roleInfoClass);
    var modified = 0;
    
    Process.enumerateRanges('rw-').forEach(function(range) {
        if (range.size < 0x100 || range.size > 200*1024*1024) return;
        if (range.file && range.file.path &&
            (range.file.path.indexOf('.so') !== -1 || range.file.path.indexOf('/dev/') !== -1)) return;
        try {
            Memory.scanSync(range.base, range.size, klassPattern).forEach(function(match) {
                var addr = match.address;
                if (parseInt(addr.toString(16),16) % 8 !== 0) return;
                try {
                    var monitor = addr.add(8).readPointer();
                    var monVal = parseInt(monitor.toString(16),16);
                    if (monVal !== 0 && monVal < 0x10000) return;
                    var roleId = addr.add(0x10).readS32();
                    if (roleId < 0 || roleId > 200) return;
                    var maxHp = addr.add(0x14).readS32();
                    if (maxHp < 0 || maxHp > 99999) return;
                    var curHp = addr.add(0x18).readS32();
                    if (curHp < 0 || curHp > 99999) return;
                    var level = addr.add(0x24).readS32();
                    if (level < 0 || level > 100) return;
                    
                    var oldGold = addr.add(0x2c).readS32();
                    addr.add(0x2c).writeS32(amount);
                    modified++;
                    send({t:"log", m:"💰 Gold: " + oldGold + " -> " + amount});
                } catch(e) {}
            });
        } catch(e) {}
    });
    return modified > 0 ? "✅ 金币已修改为 " + amount : "⚠️ 未找到实例(需在游戏对局中)";
}

function doResetSkillCD() {
    if (!g_api) return "APIs not ready";
    var klassPattern = ptrToLePattern(g_roleInfoClass);
    var resetCount = 0;
    
    Process.enumerateRanges('rw-').forEach(function(range) {
        if (range.size < 0x100 || range.size > 200*1024*1024) return;
        if (range.file && range.file.path &&
            (range.file.path.indexOf('.so') !== -1 || range.file.path.indexOf('/dev/') !== -1)) return;
        try {
            Memory.scanSync(range.base, range.size, klassPattern).forEach(function(match) {
                var addr = match.address;
                if (parseInt(addr.toString(16),16) % 8 !== 0) return;
                try {
                    var monitor = addr.add(8).readPointer();
                    var monVal = parseInt(monitor.toString(16),16);
                    if (monVal !== 0 && monVal < 0x10000) return;
                    var roleId = addr.add(0x10).readS32();
                    if (roleId < 0 || roleId > 200) return;
                    var maxHp = addr.add(0x14).readS32();
                    if (maxHp < 0 || maxHp > 99999) return;
                    var curHp = addr.add(0x18).readS32();
                    if (curHp < 0 || curHp > 99999) return;
                    var level = addr.add(0x24).readS32();
                    if (level < 0 || level > 100) return;
                    
                    // dungeonSkill
                    try {
                        var ds = addr.add(0x80).readPointer();
                        if (!ds.isNull() && parseInt(ds.toString(16),16) > 0x10000) {
                            var cd = ds.add(0x14).readS32();
                            if (cd > 0) { ds.add(0x14).writeS32(0); resetCount++; }
                        }
                    } catch(e) {}
                    
                    // skills list
                    try {
                        var sl = addr.add(0x88).readPointer();
                        if (!sl.isNull() && parseInt(sl.toString(16),16) > 0x10000) {
                            var items = sl.add(0x10).readPointer();
                            var sz = sl.add(0x18).readS32();
                            if (sz > 0 && sz < 100 && !items.isNull()) {
                                var eb = items.add(0x20);
                                for (var i = 0; i < sz; i++) {
                                    var so = eb.add(i * Process.pointerSize).readPointer();
                                    if (so.isNull()) continue;
                                    var scd = so.add(0x14).readS32();
                                    if (scd > 0) { so.add(0x14).writeS32(0); resetCount++; }
                                }
                            }
                        }
                    } catch(e) {}
                } catch(e) {}
            });
        } catch(e) {}
    });
    return resetCount > 0 ? "✅ 已重置 " + resetCount + " 个技能CD" : "⚠️ 未找到需要重置的技能";
}

// ============ 创建悬浮窗 ============
function createOverlay() {
    if (g_overlayCreated) return;
    
    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var currentApp = ActivityThread.currentApplication();
        var context = currentApp.getApplicationContext();
        
        var WindowManager = Java.use("android.view.WindowManager");
        var WindowManagerLayoutParams = Java.use("android.view.WindowManager$LayoutParams");
        var Gravity = Java.use("android.view.Gravity");
        var PixelFormat = Java.use("android.graphics.PixelFormat");
        var Color = Java.use("android.graphics.Color");
        var ViewGroup = Java.use("android.view.ViewGroup");
        var LinearLayout = Java.use("android.widget.LinearLayout");
        var TextView = Java.use("android.widget.TextView");
        var Button = Java.use("android.widget.Button");
        var EditText = Java.use("android.widget.EditText");
        var View = Java.use("android.view.View");
        var InputType = Java.use("android.text.InputType");
        var TypedValue = Java.use("android.util.TypedValue");
        var GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
        var MotionEvent = Java.use("android.view.MotionEvent");
        var Handler = Java.use("android.os.Handler");
        var Looper = Java.use("android.os.Looper");
        
        var handler = Handler.$new(Looper.getMainLooper());
        
        handler.post(Java.registerClass({
            name: "com.hack.OverlayCreator",
            implements: [Java.use("java.lang.Runnable")],
            methods: {
                run: function() {
                    try {
                        _createOverlayUI(context);
                    } catch(e) {
                        send({t:"error", m:"Overlay creation failed: " + e});
                    }
                }
            }
        }).$new());
    });
}

function _createOverlayUI(context) {
    var WindowManager = Java.use("android.view.WindowManager");
    var WindowManagerLayoutParams = Java.use("android.view.WindowManager$LayoutParams");
    var Gravity = Java.use("android.view.Gravity");
    var PixelFormat = Java.use("android.graphics.PixelFormat");
    var Color = Java.use("android.graphics.Color");
    var LinearLayout = Java.use("android.widget.LinearLayout");
    var TextView = Java.use("android.widget.TextView");
    var Button = Java.use("android.widget.Button");
    var EditText = Java.use("android.widget.EditText");
    var View = Java.use("android.view.View");
    var InputType = Java.use("android.text.InputType");
    var TypedValue = Java.use("android.util.TypedValue");
    var GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
    var MotionEvent = Java.use("android.view.MotionEvent");
    var ViewGroupLP = Java.use("android.view.ViewGroup$LayoutParams");
    var LinearLayoutLP = Java.use("android.widget.LinearLayout$LayoutParams");
    
    var JavaString = Java.use("java.lang.String");
    var CharSequence = Java.use("java.lang.CharSequence");
    var TextViewClass = Java.use("android.widget.TextView");
    
    function jstr(s) { return Java.cast(JavaString.$new("" + s), CharSequence); }
    
    // 使用 setText(char[], int, int) 重载，绕开 CharSequence/BufferType 问题
    function toCharArray(s) {
        var str = "" + s;
        var arr = [];
        for (var i = 0; i < str.length; i++) arr.push(str.charCodeAt(i));
        return Java.array('char', arr);
    }
    function setViewText(view, text) {
        var str = "" + text;
        var tv = Java.cast(view, TextViewClass);
        tv.setText.overload('[C', 'int', 'int').call(tv, toCharArray(str), 0, str.length);
    }
    function setViewHint(view, text) {
        var tv = Java.cast(view, TextViewClass);
        tv.setHint.overload('java.lang.CharSequence').call(tv, jstr(text));
    }
    
    var dp = context.getResources().getDisplayMetrics().density.value;
    
    function dpToPx(d) { return Math.round(d * dp); }
    
    // ===== 主容器 =====
    var container = LinearLayout.$new(context);
    container.setOrientation(LinearLayout.VERTICAL.value);
    container.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(10));
    
    var bgDrawable = GradientDrawable.$new();
    bgDrawable.setColor(Color.parseColor("#DD1A1A2E"));
    bgDrawable.setCornerRadius(dpToPx(14));
    bgDrawable.setStroke(dpToPx(1), Color.parseColor("#7C3AED"));
    container.setBackground(bgDrawable);
    
    // ===== 标题栏 =====
    var titleBar = LinearLayout.$new(context);
    titleBar.setOrientation(LinearLayout.HORIZONTAL.value);
    titleBar.setGravity(Gravity.CENTER_VERTICAL.value);
    var titleLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, ViewGroupLP.WRAP_CONTENT.value);
    titleBar.setLayoutParams(titleLP);
    
    var title = TextView.$new(context);
    setViewText(title, "🌕 月圆之夜");
    title.setTextColor(Color.parseColor("#E0E7FF"));
    title.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 15);
    var tLP = LinearLayoutLP.$new(0, ViewGroupLP.WRAP_CONTENT.value, 1.0);
    title.setLayoutParams(tLP);
    titleBar.addView(title);
    
    // 最小化/关闭按钮
    var toggleBtn = Button.$new(context);
    setViewText(toggleBtn, "—");
    toggleBtn.setTextColor(Color.parseColor("#A5B4FC"));
    toggleBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 12);
    var toggleBg = GradientDrawable.$new();
    toggleBg.setColor(Color.parseColor("#33FFFFFF"));
    toggleBg.setCornerRadius(dpToPx(8));
    toggleBtn.setBackground(toggleBg);
    toggleBtn.setPadding(dpToPx(10), 0, dpToPx(10), 0);
    var tbLP = LinearLayoutLP.$new(ViewGroupLP.WRAP_CONTENT.value, dpToPx(28));
    tbLP.setMargins(dpToPx(6), 0, 0, 0);
    toggleBtn.setLayoutParams(tbLP);
    titleBar.addView(toggleBtn);
    
    container.addView(titleBar);
    
    // ===== 内容区（可折叠）=====
    var contentArea = LinearLayout.$new(context);
    contentArea.setOrientation(LinearLayout.VERTICAL.value);
    var caLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, ViewGroupLP.WRAP_CONTENT.value);
    caLP.setMargins(0, dpToPx(6), 0, 0);
    contentArea.setLayoutParams(caLP);
    
    // --- 分割线 ---
    var div1 = View.$new(context);
    div1.setBackgroundColor(Color.parseColor("#333366"));
    var dLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, dpToPx(1));
    dLP.setMargins(0, dpToPx(4), 0, dpToPx(6));
    div1.setLayoutParams(dLP);
    contentArea.addView(div1);
    
    // --- 金币区域 ---
    var goldLabel = TextView.$new(context);
    setViewText(goldLabel, "💰 金币修改");
    goldLabel.setTextColor(Color.parseColor("#FCD34D"));
    goldLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 13);
    contentArea.addView(goldLabel);
    
    var goldRow = LinearLayout.$new(context);
    goldRow.setOrientation(LinearLayout.HORIZONTAL.value);
    goldRow.setGravity(Gravity.CENTER_VERTICAL.value);
    var grLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, ViewGroupLP.WRAP_CONTENT.value);
    grLP.setMargins(0, dpToPx(4), 0, 0);
    goldRow.setLayoutParams(grLP);
    
    var goldInput = EditText.$new(context);
    setViewHint(goldInput, "输入金币");
    setViewText(goldInput, "99999");
    goldInput.setTextColor(Color.WHITE.value);
    goldInput.setHintTextColor(Color.parseColor("#666688"));
    goldInput.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 13);
    goldInput.setInputType(InputType.TYPE_CLASS_NUMBER.value);
    goldInput.setPadding(dpToPx(8), dpToPx(4), dpToPx(8), dpToPx(4));
    goldInput.setSingleLine(true);
    var giBg = GradientDrawable.$new();
    giBg.setColor(Color.parseColor("#1E1E3F"));
    giBg.setCornerRadius(dpToPx(6));
    giBg.setStroke(dpToPx(1), Color.parseColor("#4338CA"));
    goldInput.setBackground(giBg);
    var giLP = LinearLayoutLP.$new(0, ViewGroupLP.WRAP_CONTENT.value, 1.0);
    goldInput.setLayoutParams(giLP);
    goldRow.addView(goldInput);
    
    var goldBtn = _makeButton(context, "修改", "#7C3AED", dp);
    var gbLP = LinearLayoutLP.$new(ViewGroupLP.WRAP_CONTENT.value, dpToPx(32));
    gbLP.setMargins(dpToPx(6), 0, 0, 0);
    goldBtn.setLayoutParams(gbLP);
    goldRow.addView(goldBtn);
    
    contentArea.addView(goldRow);
    
    // --- 快捷金币按钮 ---
    var quickRow = LinearLayout.$new(context);
    quickRow.setOrientation(LinearLayout.HORIZONTAL.value);
    var qrLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, ViewGroupLP.WRAP_CONTENT.value);
    qrLP.setMargins(0, dpToPx(4), 0, 0);
    quickRow.setLayoutParams(qrLP);
    
    var presets = [9999, 99999, 888888, 999999];
    for (var pi = 0; pi < presets.length; pi++) {
        var qb = _makeButton(context, "" + presets[pi], "#374151", dp);
        qb.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 10);
        var qbLP = LinearLayoutLP.$new(0, dpToPx(26), 1.0);
        if (pi > 0) qbLP.setMargins(dpToPx(3), 0, 0, 0);
        qb.setLayoutParams(qbLP);
        // 点击设置到输入框
        (function(val, btn) {
            btn.setOnClickListener(Java.registerClass({
                name: "com.hack.PresetClick" + val,
                implements: [Java.use("android.view.View$OnClickListener")],
                methods: {
                    onClick: function(v) {
                        setViewText(goldInput, val);
                    }
                }
            }).$new());
        })(presets[pi], qb);
        quickRow.addView(qb);
    }
    contentArea.addView(quickRow);
    
    // --- 分割线 ---
    var div2 = View.$new(context);
    div2.setBackgroundColor(Color.parseColor("#333366"));
    var d2LP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, dpToPx(1));
    d2LP.setMargins(0, dpToPx(8), 0, dpToPx(6));
    div2.setLayoutParams(d2LP);
    contentArea.addView(div2);
    
    // --- 技能CD区域 ---
    var skillLabel = TextView.$new(context);
    setViewText(skillLabel, "⚡ 探索技能");
    skillLabel.setTextColor(Color.parseColor("#67E8F9"));
    skillLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 13);
    contentArea.addView(skillLabel);
    
    var skillBtn = _makeButton(context, "重置所有技能CD", "#0E7490", dp);
    var sbLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, dpToPx(34));
    sbLP.setMargins(0, dpToPx(4), 0, 0);
    skillBtn.setLayoutParams(sbLP);
    contentArea.addView(skillBtn);
    
    // --- 状态文本 ---
    var statusText = TextView.$new(context);
    setViewText(statusText, "就绪");
    statusText.setTextColor(Color.parseColor("#9CA3AF"));
    statusText.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 11);
    var stLP = LinearLayoutLP.$new(ViewGroupLP.MATCH_PARENT.value, ViewGroupLP.WRAP_CONTENT.value);
    stLP.setMargins(0, dpToPx(6), 0, 0);
    statusText.setLayoutParams(stLP);
    contentArea.addView(statusText);
    
    container.addView(contentArea);
    
    // ===== WindowManager 参数 =====
    var wmParams = WindowManagerLayoutParams.$new(
        dpToPx(220),
        WindowManagerLayoutParams.WRAP_CONTENT.value,
        // TYPE_APPLICATION_OVERLAY = 2038 (Android 8+), TYPE_PHONE = 2002 (旧版)
        2,  // TYPE_APPLICATION（进程内，不需要权限）
        // FLAG_NOT_FOCUSABLE 默认不拦截按键
        WindowManagerLayoutParams.FLAG_NOT_FOCUSABLE.value,
        PixelFormat.TRANSLUCENT.value
    );
    wmParams.gravity.value = Gravity.TOP.value | Gravity.LEFT.value;
    wmParams.x.value = dpToPx(10);
    wmParams.y.value = dpToPx(100);
    
    // ===== 获取 WindowManager 并添加 =====
    var Activity = Java.use("android.app.Activity");
    var wm = Java.cast(context.getSystemService("window"), WindowManager);
    
    // 需要从 Activity 获取 WindowManager
    var ActivityThread = Java.use("android.app.ActivityThread");
    var activities = ActivityThread.currentActivityThread().mActivities.value;
    var activityRecord = null;
    var it = activities.values().iterator();
    while (it.hasNext()) {
        var ar = it.next();
        var act = ar.activity.value;
        if (act !== null) {
            activityRecord = act;
            break;
        }
    }
    
    if (!activityRecord) {
        send({t:"error", m:"No activity found for overlay"});
        return;
    }
    
    var actWm = Java.cast(activityRecord, Activity).getWindowManager();
    
    // ===== 拖动支持 =====
    var lastX = {value: 0};
    var lastY = {value: 0};
    var isDragging = {value: false};
    var initialTouchX = {value: 0};
    var initialTouchY = {value: 0};
    
    titleBar.setOnTouchListener(Java.registerClass({
        name: "com.hack.DragTouch",
        implements: [Java.use("android.view.View$OnTouchListener")],
        methods: {
            onTouch: function(v, event) {
                var action = event.getAction();
                if (action === MotionEvent.ACTION_DOWN.value) {
                    lastX.value = wmParams.x.value;
                    lastY.value = wmParams.y.value;
                    initialTouchX.value = event.getRawX();
                    initialTouchY.value = event.getRawY();
                    isDragging.value = false;
                    return true;
                } else if (action === MotionEvent.ACTION_MOVE.value) {
                    var dx = event.getRawX() - initialTouchX.value;
                    var dy = event.getRawY() - initialTouchY.value;
                    if (Math.abs(dx) > 5 || Math.abs(dy) > 5) isDragging.value = true;
                    wmParams.x.value = Math.round(lastX.value + dx);
                    wmParams.y.value = Math.round(lastY.value + dy);
                    try { actWm.updateViewLayout(container, wmParams); } catch(e) {}
                    return true;
                } else if (action === MotionEvent.ACTION_UP.value) {
                    return isDragging.value;
                }
                return false;
            }
        }
    }).$new());
    
    // ===== 折叠/展开 =====
    var collapsed = {value: false};
    toggleBtn.setOnClickListener(Java.registerClass({
        name: "com.hack.ToggleClick",
        implements: [Java.use("android.view.View$OnClickListener")],
        methods: {
            onClick: function(v) {
                collapsed.value = !collapsed.value;
                if (collapsed.value) {
                    contentArea.setVisibility(View.GONE.value);
                    setViewText(toggleBtn, "+");
                    wmParams.width.value = dpToPx(120);
                } else {
                    contentArea.setVisibility(View.VISIBLE.value);
                    setViewText(toggleBtn, "—");
                    wmParams.width.value = dpToPx(220);
                }
                try { actWm.updateViewLayout(container, wmParams); } catch(e) {}
            }
        }
    }).$new());
    
    // ===== 金币修改按钮 =====
    goldBtn.setOnClickListener(Java.registerClass({
        name: "com.hack.GoldClick",
        implements: [Java.use("android.view.View$OnClickListener")],
        methods: {
            onClick: function(v) {
                // 点击时切换为可聚焦（让输入框能用）再切回去
                var txt = goldInput.getText().toString();
                var amount = parseInt(txt);
                if (isNaN(amount) || amount < 0) {
                    setViewText(statusText, "❌ 请输入有效数字");
                    return;
                }
                setViewText(statusText, "⏳ 修改中...");
                
                // 在新线程执行修改避免卡UI
                var Thread = Java.use("java.lang.Thread");
                var Handler = Java.use("android.os.Handler");
                var Looper = Java.use("android.os.Looper");
                var mainHandler = Handler.$new(Looper.getMainLooper());
                
                Thread.$new(Java.registerClass({
                    name: "com.hack.GoldWorker",
                    implements: [Java.use("java.lang.Runnable")],
                    methods: {
                        run: function() {
                            var result = doModifyGold(amount);
                            mainHandler.post(Java.registerClass({
                                name: "com.hack.GoldResult",
                                implements: [Java.use("java.lang.Runnable")],
                                methods: { run: function() { setViewText(statusText, result); } }
                            }).$new());
                        }
                    }
                }).$new()).start();
            }
        }
    }).$new());
    
    // ===== 技能CD重置按钮 =====
    skillBtn.setOnClickListener(Java.registerClass({
        name: "com.hack.SkillClick",
        implements: [Java.use("android.view.View$OnClickListener")],
        methods: {
            onClick: function(v) {
                setViewText(statusText, "⏳ 重置中...");
                var Thread = Java.use("java.lang.Thread");
                var Handler = Java.use("android.os.Handler");
                var Looper = Java.use("android.os.Looper");
                var mainHandler = Handler.$new(Looper.getMainLooper());
                
                Thread.$new(Java.registerClass({
                    name: "com.hack.SkillWorker",
                    implements: [Java.use("java.lang.Runnable")],
                    methods: {
                        run: function() {
                            var result = doResetSkillCD();
                            mainHandler.post(Java.registerClass({
                                name: "com.hack.SkillResult",
                                implements: [Java.use("java.lang.Runnable")],
                                methods: { run: function() { setViewText(statusText, result); } }
                            }).$new());
                        }
                    }
                }).$new()).start();
            }
        }
    }).$new());
    
    // ===== 点击输入框时切换焦点模式 =====
    goldInput.setOnFocusChangeListener(Java.registerClass({
        name: "com.hack.FocusChange",
        implements: [Java.use("android.view.View$OnFocusChangeListener")],
        methods: {
            onFocusChange: function(v, hasFocus) {
                if (hasFocus) {
                    wmParams.flags.value = 0; // 可聚焦
                } else {
                    wmParams.flags.value = WindowManagerLayoutParams.FLAG_NOT_FOCUSABLE.value;
                }
                try { actWm.updateViewLayout(container, wmParams); } catch(e) {}
            }
        }
    }).$new());
    
    // 点击输入框时允许聚焦
    goldInput.setOnClickListener(Java.registerClass({
        name: "com.hack.InputClick",
        implements: [Java.use("android.view.View$OnClickListener")],
        methods: {
            onClick: function(v) {
                wmParams.flags.value = 0;
                try { actWm.updateViewLayout(container, wmParams); } catch(e) {}
                goldInput.requestFocus();
            }
        }
    }).$new());
    
    // ===== 添加到窗口 =====
    actWm.addView(container, wmParams);
    g_overlayCreated = true;
    send({t:"log", m:"🎮 悬浮窗已创建"});
}

function _makeButton(context, text, bgColor, dp) {
    var Button = Java.use("android.widget.Button");
    var Color = Java.use("android.graphics.Color");
    var GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
    var TypedValue = Java.use("android.util.TypedValue");
    
    var JavaString = Java.use("java.lang.String");
    var TextViewClass = Java.use("android.widget.TextView");
    var btn = Button.$new(context);
    var str = "" + text;
    var arr = [];
    for (var ci = 0; ci < str.length; ci++) arr.push(str.charCodeAt(ci));
    var tv = Java.cast(btn, TextViewClass);
    tv.setText.overload('[C', 'int', 'int').call(tv, Java.array('char', arr), 0, str.length);
    btn.setTextColor(Color.WHITE.value);
    btn.setTextSize(TypedValue.COMPLEX_UNIT_SP.value, 12);
    btn.setAllCaps(false);
    var bg = GradientDrawable.$new();
    bg.setColor(Color.parseColor(bgColor));
    bg.setCornerRadius(Math.round(8 * dp));
    btn.setBackground(bg);
    btn.setPadding(Math.round(10*dp), Math.round(2*dp), Math.round(10*dp), Math.round(2*dp));
    btn.setMinHeight(0);
    btn.setMinimumHeight(0);
    return btn;
}

// ============ 辅助函数 ============
function stringToPattern(str) {
    var hex = "";
    for (var i = 0; i < str.length; i++) {
        if (hex.length > 0) hex += " ";
        hex += ("0" + str.charCodeAt(i).toString(16)).slice(-2);
    }
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


def main():
    parser = argparse.ArgumentParser(description="月圆之夜 悬浮窗控制面板")
    parser.add_argument("--attach", action="store_true", help="attach 到已运行的游戏")
    args = parser.parse_args()

    print("=" * 50)
    print("  🌕 月圆之夜 - 悬浮窗控制面板")
    print("  按 Ctrl+C 断开连接")
    print("=" * 50)

    try:
        device = frida.get_usb_device(timeout=5)
        print(f"\n[*] Device: {device.name}")
    except Exception as e:
        print(f"[-] No USB device: {e}")
        return

    session = None
    script = None

    def on_message(message, data):
        if message['type'] == 'send':
            p = message['payload']
            t = p.get('t', '')
            m = p.get('m', '')
            if t == 'log':
                print(f"  [*] {m}")
            elif t == 'error':
                print(f"  [-] {m}")
        elif message['type'] == 'error':
            print(f"  [ERR] {str(message)[:200]}")

    if args.attach:
        print(f"[*] Attaching to {PACKAGE}...")
        try:
            session = device.attach(PACKAGE)
        except frida.ProcessNotFoundError:
            try:
                session = device.attach("月圆之夜")
            except:
                print("[-] Game not running")
                return
    else:
        print(f"[*] Spawning {PACKAGE}...")
        subprocess.run(["adb", "shell", f"am force-stop {PACKAGE}"], capture_output=True)
        time.sleep(1)
        pid = device.spawn([PACKAGE])
        print(f"[*] PID: {pid}")
        session = device.attach(pid)

    script = session.create_script(FRIDA_SCRIPT)
    script.on('message', on_message)
    script.load()

    if not args.attach:
        device.resume(pid)
        print("[*] Game resumed")

    print("[*] 悬浮窗将在游戏加载完成后显示(约11秒)...")
    print("[*] 保持此终端运行，按 Ctrl+C 退出\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Disconnecting...")
        try:
            script.unload()
            session.detach()
        except:
            pass
        print("[*] Done!")


if __name__ == "__main__":
    main()
