// enum_gold.js - 枚举所有类，搜索金币相关关键字
'use strict';

setTimeout(function() {
    const il2cpp = Process.findModuleByName('libil2cpp.so');
    if (!il2cpp) { send('[!] libil2cpp.so not found'); return; }
    send('[+] libil2cpp.so base=' + il2cpp.base);

    // 所有23个API的偏移量 (find_api_v8确认)
    const apiOffsets = {
        il2cpp_domain_get:            0xf47d48,
        il2cpp_thread_attach:         0xf481cc,
        il2cpp_domain_get_assemblies: 0xf47d54,
        il2cpp_assembly_get_image:    0xf47948,
        il2cpp_image_get_name:        0xf483b4,
        il2cpp_image_get_class_count: 0xf483c0,
        il2cpp_image_get_class:       0xf483d8,
        il2cpp_class_get_name:        0xf479a4,
        il2cpp_class_get_namespace:   0xf479b8,
        il2cpp_class_get_methods:     0xf4799c,
        il2cpp_method_get_name:       0xf48080,
        il2cpp_method_get_param_count:0xf48098,
        il2cpp_class_get_fields:      0xf47984,
        il2cpp_field_get_name:        0xf47f40,
        il2cpp_field_get_offset:      0xf47f48,
        il2cpp_field_get_type:        0xf47f4c,
        il2cpp_type_get_name:         0xf48230,
        il2cpp_class_get_parent:      0xf479bc,
        il2cpp_string_new:            0xf481b0,
        il2cpp_runtime_invoke:        0xf48168,
        il2cpp_class_get_type:        0xf479f0,
        il2cpp_class_from_name:       0xf47974,
        il2cpp_resolve_icall:         0xf47918,
    };

    const api = {};
    const base = il2cpp.base;
    
    api.domain_get = new NativeFunction(base.add(apiOffsets.il2cpp_domain_get), 'pointer', []);
    api.thread_attach = new NativeFunction(base.add(apiOffsets.il2cpp_thread_attach), 'pointer', ['pointer']);
    api.domain_get_assemblies = new NativeFunction(base.add(apiOffsets.il2cpp_domain_get_assemblies), 'pointer', ['pointer', 'pointer']);
    api.assembly_get_image = new NativeFunction(base.add(apiOffsets.il2cpp_assembly_get_image), 'pointer', ['pointer']);
    api.image_get_name = new NativeFunction(base.add(apiOffsets.il2cpp_image_get_name), 'pointer', ['pointer']);
    api.image_get_class_count = new NativeFunction(base.add(apiOffsets.il2cpp_image_get_class_count), 'uint32', ['pointer']);
    api.image_get_class = new NativeFunction(base.add(apiOffsets.il2cpp_image_get_class), 'pointer', ['pointer', 'uint32']);
    api.class_get_name = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_name), 'pointer', ['pointer']);
    api.class_get_namespace = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_namespace), 'pointer', ['pointer']);
    api.class_get_methods = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_methods), 'pointer', ['pointer', 'pointer']);
    api.method_get_name = new NativeFunction(base.add(apiOffsets.il2cpp_method_get_name), 'pointer', ['pointer']);
    api.method_get_param_count = new NativeFunction(base.add(apiOffsets.il2cpp_method_get_param_count), 'uint32', ['pointer']);
    api.class_get_fields = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_fields), 'pointer', ['pointer', 'pointer']);
    api.field_get_name = new NativeFunction(base.add(apiOffsets.il2cpp_field_get_name), 'pointer', ['pointer']);
    api.field_get_offset = new NativeFunction(base.add(apiOffsets.il2cpp_field_get_offset), 'uint32', ['pointer']);
    api.field_get_type = new NativeFunction(base.add(apiOffsets.il2cpp_field_get_type), 'pointer', ['pointer']);
    api.type_get_name = new NativeFunction(base.add(apiOffsets.il2cpp_type_get_name), 'pointer', ['pointer']);
    api.class_get_parent = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_parent), 'pointer', ['pointer']);
    api.string_new = new NativeFunction(base.add(apiOffsets.il2cpp_string_new), 'pointer', ['pointer']);
    api.runtime_invoke = new NativeFunction(base.add(apiOffsets.il2cpp_runtime_invoke), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    api.class_get_type = new NativeFunction(base.add(apiOffsets.il2cpp_class_get_type), 'pointer', ['pointer']);
    api.class_from_name = new NativeFunction(base.add(apiOffsets.il2cpp_class_from_name), 'pointer', ['pointer', 'pointer', 'pointer']);
    api.resolve_icall = new NativeFunction(base.add(apiOffsets.il2cpp_resolve_icall), 'pointer', ['pointer']);

    // 初始化
    const domain = api.domain_get();
    send('[+] domain = ' + domain);
    if (domain.isNull()) { send('[!] domain is null'); return; }
    
    const thread = api.thread_attach(domain);
    send('[+] thread = ' + thread);

    // 获取所有assemblies
    const sizePtr = Memory.alloc(8);
    sizePtr.writeU64(0);
    const assembliesPtr = api.domain_get_assemblies(domain, sizePtr);
    const numAssemblies = sizePtr.readU32();
    send('[+] assemblies: ' + numAssemblies);

    // 金币相关关键字
    const keywords = ['gold', 'coin', 'money', 'currency', 'wealth', 'reward',
                      'shop', 'store', 'purchase', 'buy', 'price', 'cost',
                      'item', 'inventory', 'wallet', 'pay', 'diamond', 'gem',
                      'player', 'userdata', 'gamedata', 'savedata', 'data',
                      'resource', 'economy', 'treasure', 'loot', 'chest',
                      'cardgame', 'battle', 'hero', 'character', 'stat',
                      'buff', 'attribute', 'upgrade', 'level', 'exp',
                      'score', 'achievement', 'dungeon', 'quest', 'mission',
                      'equip', 'weapon', 'armor', 'skill', 'talent',
                      'energy', 'stamina', 'heart', 'hp', 'health',
                      'attack', 'defense', 'damage', 'power',
                      'nightoffullmoon', 'yyzy', 'athena',
                      'card', 'deck', 'hand', 'round', 'turn',
                      'bag', 'pack', 'relic', 'potion', 'elixir',
                      'class', 'knight', 'witch', 'nun', 'ranger',
                      'monster', 'boss', 'enemy', 'npc',
                      'event', 'encounter', 'map', 'node', 'path',
                      'save', 'load', 'config', 'setting', 'manager',
                      'ui', 'panel', 'window', 'dialog', 'menu',
                      'game', 'main', 'scene', 'module', 'system',
                      'account', 'user', 'profile', 'info',
                      'prop', 'asset', 'bundle', 'token', 'point',
                      'gift', 'bonus', 'daily', 'signin', 'checkin',
                      'gacha', 'draw', 'summon', 'roll', 'spin',
                      'vip', 'premium', 'subscribe', 'iap'];

    let totalClasses = 0;
    const matchedClasses = [];
    const allClassNames = []; // 保存所有类名用于后续分析

    function safeReadUtf8(p) {
        try {
            if (p.isNull()) return '';
            return p.readUtf8String() || '';
        } catch(e) { return ''; }
    }

    // 遍历所有assemblies
    for (let i = 0; i < numAssemblies; i++) {
        const assembly = assembliesPtr.add(i * Process.pointerSize).readPointer();
        if (assembly.isNull()) continue;

        let image;
        try { image = api.assembly_get_image(assembly); } catch(e) { continue; }
        if (!image || image.isNull()) continue;

        const imageName = safeReadUtf8(api.image_get_name(image));
        let classCount;
        try { classCount = api.image_get_class_count(image); } catch(e) { continue; }
        
        send('[*] Assembly ' + i + ': ' + imageName + ' (' + classCount + ' classes)');

        for (let j = 0; j < classCount; j++) {
            let klass;
            try { klass = api.image_get_class(image, j); } catch(e) { continue; }
            if (!klass || klass.isNull()) continue;

            const className = safeReadUtf8(api.class_get_name(klass));
            const nameSpace = safeReadUtf8(api.class_get_namespace(klass));
            const fullName = (nameSpace ? nameSpace + '.' : '') + className;
            totalClasses++;
            allClassNames.push(fullName);

            // 检查是否匹配关键字
            const lower = fullName.toLowerCase();
            let matched = false;
            for (const kw of keywords) {
                if (lower.indexOf(kw.toLowerCase()) >= 0) {
                    matched = true;
                    break;
                }
            }

            if (matched) {
                // 获取字段
                const fields = [];
                try {
                    const iterPtr = Memory.alloc(8);
                    iterPtr.writePointer(ptr(0));
                    for (let fi = 0; fi < 200; fi++) {
                        const field = api.class_get_fields(klass, iterPtr);
                        if (field.isNull()) break;
                        const fname = safeReadUtf8(api.field_get_name(field));
                        const foffset = api.field_get_offset(field);
                        let ftypeName = '';
                        try {
                            const ftype = api.field_get_type(field);
                            if (!ftype.isNull()) {
                                const tn = api.type_get_name(ftype);
                                ftypeName = safeReadUtf8(tn);
                            }
                        } catch(e) {}
                        fields.push({ name: fname, offset: foffset, type: ftypeName });
                    }
                } catch(e) {}

                // 获取方法
                const methods = [];
                try {
                    const iterPtr = Memory.alloc(8);
                    iterPtr.writePointer(ptr(0));
                    for (let mi = 0; mi < 500; mi++) {
                        const method = api.class_get_methods(klass, iterPtr);
                        if (method.isNull()) break;
                        const mname = safeReadUtf8(api.method_get_name(method));
                        const mpc = api.method_get_param_count(method);
                        methods.push({ name: mname, paramCount: mpc });
                    }
                } catch(e) {}

                // 获取父类
                let parentName = '';
                try {
                    const parent = api.class_get_parent(klass);
                    if (!parent.isNull()) {
                        const pn = safeReadUtf8(api.class_get_name(parent));
                        const pns = safeReadUtf8(api.class_get_namespace(parent));
                        parentName = (pns ? pns + '.' : '') + pn;
                    }
                } catch(e) {}

                matchedClasses.push({
                    fullName: fullName,
                    image: imageName,
                    parent: parentName,
                    klass: klass.toString(),
                    fields: fields,
                    methods: methods
                });
            }
        }
    }

    send('\n[+] Total classes scanned: ' + totalClasses);
    send('[+] Matched classes: ' + matchedClasses.length);

    // 输出所有类名列表(每50个一行)
    send('\n[*] All class names (' + allClassNames.length + '):');
    for (let k = 0; k < allClassNames.length; k += 50) {
        const batch = allClassNames.slice(k, k+50);
        send('  ' + batch.join(', '));
    }

    // 输出匹配的类详情
    for (const cls of matchedClasses) {
        send('\n=== ' + cls.fullName + ' ===');
        send('  Image: ' + cls.image + '  Parent: ' + cls.parent + '  Klass: ' + cls.klass);
        if (cls.fields.length > 0) {
            send('  Fields (' + cls.fields.length + '):');
            for (const f of cls.fields) {
                send('    [0x' + f.offset.toString(16) + '] ' + f.type + ' ' + f.name);
            }
        }
        if (cls.methods.length > 0) {
            send('  Methods (' + cls.methods.length + '):');
            for (const m of cls.methods) {
                send('    ' + m.name + '(' + m.paramCount + ' params)');
            }
        }
    }

    send('\n=== ENUM DONE ===');
}, 8000);
