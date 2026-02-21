/*
 * gold_hack.c - 月圆之夜 金币修改器 (native .so) + 游戏内悬浮菜单
 *
 * 功能:
 *   1. 注入后自动查找 il2cpp API（兼容 MHP 保护）
 *   2. 通过 JNI 加载嵌入的 DEX，创建游戏内悬浮菜单
 *   3. 菜单按钮回调 native 方法实时修改金币 / 重置技能 CD
 *
 * 编译: aarch64-linux-android35-clang -shared -fPIC -O2 -o libgoldhack.so gold_hack.c -llog
 * 注入: 通过 Frida / zygisk / ptrace 注入到 com.ztgame.yyzy 进程
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>
#include <jni.h>
#include <android/log.h>

// ========== 嵌入的 DEX 字节码（由 CI 通过 -include overlay_dex.h 注入）==========
// overlay_dex_data[] 和 overlay_dex_data_len 由编译器 -include 标志提供
// 同时定义 -DOVERLAY_DEX 启用悬浮菜单功能

// ========== 配置 ==========
#ifndef TARGET_GOLD
#define TARGET_GOLD     99999       // 目标金币值，编译时可用 -DTARGET_GOLD=888888 覆盖
#endif
#ifndef WAIT_SECONDS
#define WAIT_SECONDS    2          // v6.34: 减少等待 (早期Execute hook不依赖API初始化)
#endif

// ========== RoleInfo 字段偏移定义 ==========
// 从 dump.txt 中 RoleInfo 类提取 (Assembly-CSharp.dll)
#define OFF_ROLEID      0x10
#define OFF_MODEID      0x14
#define OFF_MAXHP       0x18
#define OFF_CURHP       0x1c
#define OFF_CURMP       0x20
#define OFF_CUREXP      0x24
#define OFF_CURVESSEL   0x28
#define OFF_CURGOLD     0x2c
#define OFF_HANDCARDS   0x30
#define OFF_LEVEL       0x34
#define OFF_CURACTION   0x38
#define OFF_AREA        0x3c
#define OFF_REPUTATION  0x40
#define OFF_COURAGE     0x48
#define OFF_DUNGEONSKILL 0x80
#define OFF_SKILLS      0x88
#define OFF_CARDSLIBRARY 0x90
#define OFF_EQUIPSLOT   0x98
#define OFF_TALENTBUFF  0xa0
#define OFF_EVENTBUFF   0xb0
#define OFF_LOSTTHING   0xb8
#define OFF_APPEARLT    0xc0
#define OFF_CURSELIST   0xd0
#define OFF_POCKETS     0xe0
#define MAX_API_STRINGS 300         // 最大 il2cpp API 字符串数
#define MAX_SCAN_SIZE   (200*1024*1024)  // 单个内存区域最大扫描大小

#define LOG_TAG "GoldHack v6.35"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 全局互斥锁：保护内存扫描（parse_maps / SIGSEGV handler / g_regions 等全局状态）
static pthread_mutex_t g_hack_mutex = PTHREAD_MUTEX_INITIALIZER;

// ========== il2cpp API 类型定义 ==========
typedef void* Il2CppDomain;
typedef void* Il2CppThread;
typedef void* Il2CppAssembly;
typedef void* Il2CppImage;
typedef void* Il2CppClass;
typedef void* Il2CppMethodInfo;
typedef void* Il2CppFieldInfo;
typedef void* Il2CppObject;
typedef void* Il2CppMethodInfo;

// API 函数指针类型
typedef Il2CppDomain   (*il2cpp_domain_get_t)(void);
typedef Il2CppThread   (*il2cpp_thread_attach_t)(Il2CppDomain domain);
typedef Il2CppAssembly*(*il2cpp_domain_get_assemblies_t)(Il2CppDomain domain, size_t *count);
typedef Il2CppImage    (*il2cpp_assembly_get_image_t)(Il2CppAssembly assembly);
typedef const char*    (*il2cpp_image_get_name_t)(Il2CppImage image);
typedef Il2CppClass    (*il2cpp_class_from_name_t)(Il2CppImage image, const char *ns, const char *name);
typedef int            (*il2cpp_image_get_class_count_t)(Il2CppImage image);
typedef Il2CppClass    (*il2cpp_image_get_class_t)(Il2CppImage image, int index);
typedef const char*    (*il2cpp_class_get_name_t)(Il2CppClass klass);
typedef const char*    (*il2cpp_class_get_namespace_t)(Il2CppClass klass);
// 新增 API：方法/字段枚举 + method hooking
typedef Il2CppMethodInfo (*il2cpp_class_get_methods_t)(Il2CppClass klass, void **iter);
typedef const char*      (*il2cpp_method_get_name_t)(Il2CppMethodInfo method);
typedef int              (*il2cpp_method_get_param_count_t)(Il2CppMethodInfo method);
typedef Il2CppFieldInfo  (*il2cpp_class_get_fields_t)(Il2CppClass klass, void **iter);
typedef const char*      (*il2cpp_field_get_name_t)(Il2CppFieldInfo field);
typedef int              (*il2cpp_field_get_offset_t)(Il2CppFieldInfo field);
typedef Il2CppMethodInfo (*il2cpp_class_get_method_from_name_t)(Il2CppClass klass, const char *name, int param_count);
typedef Il2CppObject     (*il2cpp_runtime_invoke_t)(Il2CppMethodInfo method, void *obj, void **params, void **exc);
typedef void*            (*il2cpp_string_new_t)(const char *str);
typedef Il2CppObject     (*il2cpp_object_new_t)(Il2CppClass klass);
typedef void             (*il2cpp_field_get_value_t)(void *obj, Il2CppFieldInfo field, void *value);
typedef void             (*il2cpp_field_set_value_t)(void *obj, Il2CppFieldInfo field, void *value);
typedef Il2CppClass      (*il2cpp_method_get_class_t)(Il2CppMethodInfo method);
typedef Il2CppClass      (*il2cpp_object_get_class_t)(Il2CppObject obj);
typedef Il2CppImage      (*il2cpp_class_get_image_t)(Il2CppClass klass);
typedef Il2CppClass      (*il2cpp_class_get_parent_t)(Il2CppClass klass);
// v6.26: 新增 API 用于从字段类型创建 HashSet<int>
typedef void*            (*il2cpp_field_get_type_t)(Il2CppFieldInfo field);   // returns Il2CppType*
typedef Il2CppClass      (*il2cpp_class_from_il2cpp_type_t)(void *type);      // Il2CppType* -> Il2CppClass*

// 需要发现的 API 列表
typedef struct {
    const char *name;
    void       **func_ptr;
} ApiEntry;

// 全局 API 函数指针
static il2cpp_domain_get_t             fn_domain_get = NULL;
static il2cpp_thread_attach_t          fn_thread_attach = NULL;
static il2cpp_domain_get_assemblies_t  fn_domain_get_assemblies = NULL;
static il2cpp_assembly_get_image_t     fn_assembly_get_image = NULL;
static il2cpp_image_get_name_t         fn_image_get_name = NULL;
static il2cpp_class_from_name_t        fn_class_from_name = NULL;
// 新增 API 函数指针
static il2cpp_class_get_methods_t          fn_class_get_methods = NULL;
static il2cpp_method_get_name_t            fn_method_get_name = NULL;
static il2cpp_method_get_param_count_t     fn_method_get_param_count = NULL;
static il2cpp_class_get_fields_t           fn_class_get_fields = NULL;
static il2cpp_field_get_name_t             fn_field_get_name = NULL;
static il2cpp_field_get_offset_t           fn_field_get_offset = NULL;
static il2cpp_class_get_method_from_name_t fn_class_get_method_from_name = NULL;
static il2cpp_runtime_invoke_t             fn_runtime_invoke = NULL;
static il2cpp_string_new_t                 fn_string_new = NULL;
static il2cpp_object_new_t                 fn_object_new = NULL;
static il2cpp_field_get_value_t            fn_field_get_value = NULL;
static il2cpp_field_set_value_t            fn_field_set_value = NULL;
static il2cpp_method_get_class_t           fn_method_get_class = NULL;
static il2cpp_object_get_class_t           fn_object_get_class = NULL;
static il2cpp_class_get_image_t            fn_class_get_image = NULL;
static il2cpp_class_get_parent_t           fn_class_get_parent = NULL;
static il2cpp_class_get_name_t             fn_class_get_name = NULL;
static il2cpp_class_get_namespace_t        fn_class_get_namespace = NULL;
// v6.26
static il2cpp_field_get_type_t             fn_field_get_type = NULL;
static il2cpp_class_from_il2cpp_type_t     fn_class_from_type = NULL;

static ApiEntry g_api_table[] = {
    { "il2cpp_domain_get",                 (void**)&fn_domain_get },
    { "il2cpp_thread_attach",              (void**)&fn_thread_attach },
    { "il2cpp_domain_get_assemblies",      (void**)&fn_domain_get_assemblies },
    { "il2cpp_assembly_get_image",         (void**)&fn_assembly_get_image },
    { "il2cpp_image_get_name",             (void**)&fn_image_get_name },
    { "il2cpp_class_from_name",            (void**)&fn_class_from_name },
    { "il2cpp_class_get_methods",          (void**)&fn_class_get_methods },
    { "il2cpp_method_get_name",            (void**)&fn_method_get_name },
    { "il2cpp_method_get_param_count",     (void**)&fn_method_get_param_count },
    { "il2cpp_class_get_fields",           (void**)&fn_class_get_fields },
    { "il2cpp_field_get_name",             (void**)&fn_field_get_name },
    { "il2cpp_field_get_offset",           (void**)&fn_field_get_offset },
    { "il2cpp_class_get_method_from_name", (void**)&fn_class_get_method_from_name },
    { "il2cpp_runtime_invoke",             (void**)&fn_runtime_invoke },
    { "il2cpp_string_new",                 (void**)&fn_string_new },
    { "il2cpp_object_new",                 (void**)&fn_object_new },
    { "il2cpp_field_get_value",            (void**)&fn_field_get_value },
    { "il2cpp_field_set_value",            (void**)&fn_field_set_value },
    { "il2cpp_method_get_class",           (void**)&fn_method_get_class },
    { "il2cpp_object_get_class",           (void**)&fn_object_get_class },
    { "il2cpp_class_get_image",            (void**)&fn_class_get_image },
    { "il2cpp_class_get_parent",           (void**)&fn_class_get_parent },
    { "il2cpp_class_get_name",             (void**)&fn_class_get_name },
    { "il2cpp_class_get_namespace",         (void**)&fn_class_get_namespace },
    // v6.26: 新增 API
    { "il2cpp_field_get_type",               (void**)&fn_field_get_type },
    { "il2cpp_class_from_il2cpp_type",       (void**)&fn_class_from_type },
    { NULL, NULL }
};

#define API_COUNT 26

// ========== 内存区域信息 ==========
typedef struct {
    uintptr_t start;
    uintptr_t end;
    int       readable;
    int       writable;
    int       executable;
    int       is_private;  // p = private
    char      path[512];
} MemRegion;

#define MAX_REGIONS 8192
static MemRegion g_regions[MAX_REGIONS];
static int       g_region_count = 0;

// il2cpp 字符串发现结果
typedef struct {
    uintptr_t   addr;       // 字符串在内存中的地址
    const char *api_name;   // 对应的 API 名字
    int         api_index;  // 在 g_api_table 中的索引
} StringMatch;

static StringMatch g_string_matches[MAX_API_STRINGS];
static int         g_string_match_count = 0;

// ========== 解析 /proc/self/maps ==========
static int parse_maps(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Cannot open /proc/self/maps");
        return -1;
    }

    g_region_count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp) && g_region_count < MAX_REGIONS) {
        MemRegion *r = &g_regions[g_region_count];
        char perms[8] = {0};
        unsigned long long start, end, offset, inode;
        unsigned int dev_major, dev_minor;
        char path[512] = {0};

        int n = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %511[^\n]",
                       &start, &end, perms, &offset, &dev_major, &dev_minor, &inode, path);
        if (n < 7) continue;

        r->start      = start;
        r->end        = end;
        r->readable   = (perms[0] == 'r');
        r->writable   = (perms[1] == 'w');
        r->executable = (perms[2] == 'x');
        r->is_private = (perms[3] == 'p');
        
        // 去掉 path 前面的空格
        char *p = path;
        while (*p == ' ') p++;
        strncpy(r->path, p, sizeof(r->path) - 1);
        
        g_region_count++;
    }
    fclose(fp);
    LOGI("Parsed %d memory regions", g_region_count);
    return 0;
}

// ========== 查找 libil2cpp.so 基地址 ==========
static uintptr_t find_il2cpp_base(void) {
    for (int i = 0; i < g_region_count; i++) {
        if (strstr(g_regions[i].path, "libil2cpp.so") &&
            g_regions[i].readable && g_regions[i].executable) {
            LOGI("libil2cpp.so base: 0x%" PRIxPTR, g_regions[i].start);
            return g_regions[i].start;
        }
    }
    return 0;
}

// 计算 libil2cpp.so ELF header 哈希（前256字节，稳定不受 ASLR 影响）
static uint64_t get_il2cpp_elf_hash(uintptr_t il2cpp_base) {
    // FNV-1a 64-bit
    uint64_t hash = 0xcbf29ce484222325ULL;
    const uint8_t *p = (const uint8_t *)il2cpp_base;
    for (int i = 0; i < 256; i++) {
        hash ^= p[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

// ========== API 偏移缓存（加速下次启动）==========
#define API_CACHE_MAGIC 0x47484B43  // "GHKC"
#define API_CACHE_FILENAME "goldhack_api.bin"

// 运行时获取缓存文件路径（从 /proc/self/cmdline 读包名 → /data/user/0/<pkg>/cache/）
static char g_cache_path[512] = {0};

static const char *get_cache_path(void) {
    if (g_cache_path[0]) return g_cache_path;

    char pkg[256] = {0};
    FILE *fp = fopen("/proc/self/cmdline", "r");
    if (fp) {
        fread(pkg, 1, sizeof(pkg) - 1, fp);
        fclose(fp);
    }
    // cmdline 可能含尾部 NUL/参数，只取第一段
    for (int i = 0; i < (int)sizeof(pkg); i++) {
        if (pkg[i] == '\0' || pkg[i] == '\n') { pkg[i] = '\0'; break; }
    }
    if (pkg[0] == '\0') {
        strncpy(pkg, "com.ztgame.yyzy", sizeof(pkg) - 1); // fallback
    }

    // 优先尝试 /data/user/0/<pkg>/cache/ （多用户设备标准路径）
    // 再 fallback /data/data/<pkg>/cache/
    const char *bases[] = { "/data/user/0", "/data/data", NULL };
    for (int i = 0; bases[i]; i++) {
        snprintf(g_cache_path, sizeof(g_cache_path), "%s/%s/cache", bases[i], pkg);
        // 测试目录是否可写：尝试打开一个临时文件
        char test[560];
        snprintf(test, sizeof(test), "%s/.goldhack_test", g_cache_path);
        FILE *tf = fopen(test, "w");
        if (tf) {
            fclose(tf);
            remove(test);
            LOGI("[cache] Using cache dir: %s", g_cache_path);
            // 拼接完整文件路径
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s/%s", g_cache_path, API_CACHE_FILENAME);
            strncpy(g_cache_path, tmp, sizeof(g_cache_path) - 1);
            return g_cache_path;
        }
    }
    // 都失败了，仍然用第一个路径（写入时会报错但不影响功能）
    snprintf(g_cache_path, sizeof(g_cache_path), "%s/%s/cache/%s",
             bases[0], pkg, API_CACHE_FILENAME);
    LOGW("[cache] No writable cache dir found, will use: %s", g_cache_path);
    return g_cache_path;
}

typedef struct {
    uint32_t magic;
    uint32_t api_count;
    uint64_t elf_hash;      // 校验：libil2cpp.so ELF header 哈希
    uint64_t str_offsets[API_COUNT];  // 各 API 字符串相对 il2cpp_base 的偏移
    int32_t  func_delta[API_COUNT];   // 函数指针相对 pair entry 的偏移 (func - pair_addr)
    uint64_t pair_stride;             // pair 表项间距（字节数）
} ApiCache;

// 全局记录 pair 信息（供缓存使用）
static uintptr_t g_pair_addrs[API_COUNT] = {0};

// 前向声明（这些函数/变量在后面定义，load_api_cache 需要提前引用）
static uintptr_t memmem_find_safe(uintptr_t haystack, size_t haystack_len,
                                   const void *needle, size_t needle_len);
static void install_sigsegv_handler(void);
static void uninstall_sigsegv_handler(void);
static __thread sigjmp_buf g_jmpbuf;
static __thread volatile int g_in_safe_access = 0;

static void save_api_cache(uintptr_t il2cpp_base) {
    ApiCache cache;
    memset(&cache, 0, sizeof(cache));
    cache.magic = API_CACHE_MAGIC;
    cache.api_count = API_COUNT;
    cache.elf_hash = get_il2cpp_elf_hash(il2cpp_base);
    
    // 保存字符串偏移和 func 相对 pair 的 delta
    for (int i = 0; i < API_COUNT && g_api_table[i].name; i++) {
        void *fn = *g_api_table[i].func_ptr;
        if (fn && g_pair_addrs[i]) {
            cache.str_offsets[i] = 0; // 不用，用 pair_stride 即可
            cache.func_delta[i] = (int32_t)((intptr_t)(uintptr_t)fn - (intptr_t)g_pair_addrs[i]);
        }
    }
    // 计算 pair stride（前两个 pair 的间距）
    if (g_pair_addrs[0] && g_pair_addrs[1]) {
        cache.pair_stride = (uint64_t)(g_pair_addrs[1] > g_pair_addrs[0] ?
            g_pair_addrs[1] - g_pair_addrs[0] : g_pair_addrs[0] - g_pair_addrs[1]);
    }
    
    const char *path = get_cache_path();
    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(&cache, sizeof(cache), 1, fp);
        fclose(fp);
        LOGI("[cache] Saved API cache to %s (elf_hash=0x%llx, pair_stride=%llu)",
             path, (unsigned long long)cache.elf_hash, (unsigned long long)cache.pair_stride);
    } else {
        LOGW("[cache] Failed to save cache: %s", path);
    }
}

// 返回 0=成功加载, -1=无缓存或不匹配
static int load_api_cache(uintptr_t il2cpp_base) {
    const char *path = get_cache_path();
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOGI("[cache] No cache file found");
        return -1;
    }
    
    ApiCache cache;
    size_t rd = fread(&cache, 1, sizeof(cache), fp);
    fclose(fp);
    
    if (rd != sizeof(cache) || cache.magic != API_CACHE_MAGIC || cache.api_count != API_COUNT) {
        LOGW("[cache] Cache file invalid or version mismatch");
        return -1;
    }
    
    // 校验 ELF header 哈希（检测游戏更新）
    uint64_t cur_hash = get_il2cpp_elf_hash(il2cpp_base);
    if (cache.elf_hash != cur_hash) {
        LOGW("[cache] elf_hash mismatch: cached=0x%llx cur=0x%llx (game updated?)",
             (unsigned long long)cache.elf_hash, (unsigned long long)cur_hash);
        return -1;
    }
    
    if (cache.pair_stride == 0 || cache.func_delta[0] == 0) {
        LOGW("[cache] Cache has no pair info, falling back to scan");
        return -1;
    }
    
    // 策略：在 rw- 区域搜索第一个 API 字符串的指针，然后用 stride+delta 恢复所有 API
    // 计算第一个 API 字符串的当前地址（在 libil2cpp.so 的只读段中搜索）
    const char *first_api = g_api_table[0].name;
    size_t name_len = strlen(first_api) + 1;
    uintptr_t str_addr = 0;
    
    install_sigsegv_handler();
    for (int r = 0; r < g_region_count; r++) {
        if (!g_regions[r].readable || g_regions[r].writable) continue; // 只看 r-- 或 r-x
        if (!strstr(g_regions[r].path, "libil2cpp.so")) continue;
        size_t size = g_regions[r].end - g_regions[r].start;
        if (size < name_len) continue;
        uintptr_t found = memmem_find_safe(g_regions[r].start, size, first_api, name_len);
        if (found) { str_addr = found; break; }
    }
    if (!str_addr) {
        uninstall_sigsegv_handler();
        LOGW("[cache] Cannot find string '%s' in il2cpp ro sections", first_api);
        return -1;
    }
    LOGI("[cache] Found string '%s' @ 0x%" PRIxPTR, first_api, str_addr);
    
    // 在 rw- 区域搜索包含该字符串指针的 pair entry
    uintptr_t pair0_addr = 0;
    for (int r = 0; r < g_region_count && !pair0_addr; r++) {
        if (!g_regions[r].readable || !g_regions[r].writable || g_regions[r].executable) continue;
        size_t size = g_regions[r].end - g_regions[r].start;
        if (size < 16 || size > MAX_SCAN_SIZE) continue;
        if (g_regions[r].path[0] == '\0' && size > 50 * 1024 * 1024) continue;
        
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) {
            g_in_safe_access = 0;
            continue;
        }
        for (uintptr_t a = g_regions[r].start; a <= g_regions[r].end - cache.pair_stride * API_COUNT; a += sizeof(void*)) {
            if (*(volatile uintptr_t *)a == str_addr) {
                // 验证后续条目也匹配（第二个 API 字符串在 pair+stride 处）
                uintptr_t next_name = *(volatile uintptr_t *)(a + cache.pair_stride);
                if (next_name > 0x10000 && next_name != str_addr) {
                    pair0_addr = a;
                    break;
                }
            }
        }
        g_in_safe_access = 0;
    }
    
    if (!pair0_addr) {
        uninstall_sigsegv_handler();
        LOGW("[cache] Cannot find pair table entry for '%s'", first_api);
        return -1;
    }
    LOGI("[cache] Found pair table @ 0x%" PRIxPTR " (stride=%llu)", pair0_addr, (unsigned long long)cache.pair_stride);
    
    // 从 pair table + delta 恢复所有 API
    int loaded = 0;
    for (int i = 0; i < API_COUNT && g_api_table[i].name; i++) {
        uintptr_t pair_i = pair0_addr + i * (uintptr_t)cache.pair_stride;
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t func = (uintptr_t)((intptr_t)pair_i + cache.func_delta[i]);
        g_in_safe_access = 0;
        
        // 验证函数地址对齐且可执行
        if (func % 4 != 0 || func < 0x10000) continue;
        int valid = 0;
        for (int c = 0; c < g_region_count; c++) {
            if (func >= g_regions[c].start && func < g_regions[c].end) {
                if (g_regions[c].executable) valid = 1;
                break;
            }
        }
        if (valid) {
            *g_api_table[i].func_ptr = (void *)func;
            g_pair_addrs[i] = pair_i;
            loaded++;
            LOGI("[cache] Restored %s @ %p (pair=0x%" PRIxPTR ", delta=%d)",
                 g_api_table[i].name, (void*)func, pair_i, cache.func_delta[i]);
        } else {
            LOGW("[cache] Invalid func for %s: 0x%" PRIxPTR, g_api_table[i].name, func);
        }
    }
    uninstall_sigsegv_handler();
    
    if (loaded >= 6) {
        LOGI("[cache] Restored %d/%d APIs from cache (6 core + %d optional)", loaded, API_COUNT, loaded - 6);
        return 0;
    }
    
    LOGW("[cache] Only %d/%d APIs restored (need >=6 core), falling back to scan", loaded, API_COUNT);
    for (int i = 0; g_api_table[i].name; i++) {
        *g_api_table[i].func_ptr = NULL;
    }
    return -1;
}

// ========== 安全内存读取 ==========
static int safe_read(uintptr_t addr, void *buf, size_t len) {
    // 检查地址是否在已知的可读区域内
    for (int i = 0; i < g_region_count; i++) {
        if (g_regions[i].readable &&
            addr >= g_regions[i].start &&
            addr + len <= g_regions[i].end) {
            memcpy(buf, (void*)addr, len);
            return 0;
        }
    }
    return -1;
}

// ========== 在内存中搜索字符串 ==========
static uintptr_t memmem_find(uintptr_t haystack, size_t haystack_len,
                              const void *needle, size_t needle_len) {
    if (needle_len > haystack_len) return 0;
    const uint8_t *h = (const uint8_t *)haystack;
    const uint8_t *n = (const uint8_t *)needle;
    size_t limit = haystack_len - needle_len;
    
    for (size_t i = 0; i <= limit; i++) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return haystack + i;
        }
    }
    return 0;
}

// ========== 安全内存访问（SIGSEGV 保护）==========
static struct sigaction g_old_sigsegv;
static struct sigaction g_old_sigbus;
static int g_old_saved = 0;

static void sigsegv_handler(int sig) {
    if (g_in_safe_access) {
        siglongjmp(g_jmpbuf, 1);
    }
    // 不在安全访问中，转发给原始处理器
    struct sigaction *old = (sig == SIGSEGV) ? &g_old_sigsegv : &g_old_sigbus;
    if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN && old->sa_handler != NULL) {
        old->sa_handler(sig);
        return;
    }
    // 无原始处理器，恢复默认行为
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_sigsegv_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigsegv_handler;
    sa.sa_flags = SA_RESTART;
    // 保存原始处理器（只保存一次）
    if (!g_old_saved) {
        sigaction(SIGSEGV, NULL, &g_old_sigsegv);
        sigaction(SIGBUS, NULL, &g_old_sigbus);
        g_old_saved = 1;
        LOGI("[sig] Saved original handlers: SIGSEGV=%p, SIGBUS=%p",
             (void*)g_old_sigsegv.sa_handler, (void*)g_old_sigbus.sa_handler);
    }
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

static void uninstall_sigsegv_handler(void) {
    // 恢复原始处理器，而非 SIG_DFL（MHP 可能依赖自己的 SIGSEGV handler）
    if (g_old_saved) {
        sigaction(SIGSEGV, &g_old_sigsegv, NULL);
        sigaction(SIGBUS, &g_old_sigbus, NULL);
    } else {
        signal(SIGSEGV, SIG_DFL);
        signal(SIGBUS, SIG_DFL);
    }
}

// 安全版 memmem_find，崩溃时返回 0
static uintptr_t memmem_find_safe(uintptr_t haystack, size_t haystack_len,
                                  const void *needle, size_t needle_len) {
    if (needle_len > haystack_len) return 0;
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        // SIGSEGV 发生，跳过这个区域
        g_in_safe_access = 0;
        LOGW("[scan] SIGSEGV during memmem_find_safe at 0x%" PRIxPTR, haystack);
        return 0;
    }
    uintptr_t result = memmem_find(haystack, haystack_len, needle, needle_len);
    g_in_safe_access = 0;
    return result;
}

// ========== 方法1: 通过 dlsym 尝试（正常情况下）==========
static int try_dlsym_apis(void) {
    void *handle = dlopen("libil2cpp.so", RTLD_NOLOAD);
    if (!handle) {
        LOGW("dlopen(libil2cpp.so, RTLD_NOLOAD) failed: %s", dlerror());
        return -1;
    }

    int found = 0;
    for (int i = 0; g_api_table[i].name; i++) {
        void *sym = dlsym(handle, g_api_table[i].name);
        if (sym) {
            *g_api_table[i].func_ptr = sym;
            found++;
            LOGI("[dlsym] Found %s @ %p", g_api_table[i].name, sym);
        }
    }
    
    dlclose(handle);
    LOGI("[dlsym] Found %d/%d APIs", found, API_COUNT);
    return (found == API_COUNT) ? 0 : -1;
}

// ========== 方法2: 内存扫描发现 API（绕过 MHP 保护）==========

// 检查是否每个 API 都至少有 min_copies 个字符串匹配
static int all_apis_have_strings(int min_copies) {
    for (int i = 0; i < API_COUNT && g_api_table[i].name; i++) {
        int cnt = 0;
        for (int s = 0; s < g_string_match_count; s++) {
            if (g_string_matches[s].api_index == i) cnt++;
        }
        if (cnt < min_copies) return 0;
    }
    return 1;
}

// 判断区域是否应跳过
static int should_skip_region(MemRegion *region, size_t size) {
    if (!region->readable) return 1;
    if (size < 16 || size > MAX_SCAN_SIZE) return 1;
    if (strstr(region->path, "/dev/") || strstr(region->path, "dalvik")) return 1;
    if (strstr(region->path, "/dmabuf") || strstr(region->path, "/gpu") ||
        strstr(region->path, "kgsl") || strstr(region->path, "mali")) return 1;
    if (strstr(region->path, "goldhack") || strstr(region->path, "Inject So")) return 1;
    return 0;
}

// 在单个区域中搜索所有 API 字符串
static void scan_region_for_strings(MemRegion *region) {
    size_t size = region->end - region->start;
    for (int api_idx = 0; g_api_table[api_idx].name && g_string_match_count < MAX_API_STRINGS; api_idx++) {
        const char *api_name = g_api_table[api_idx].name;
        size_t name_len = strlen(api_name) + 1;
        uintptr_t search_start = region->start;
        size_t remaining = size;
        while (remaining >= name_len && g_string_match_count < MAX_API_STRINGS) {
            uintptr_t found = memmem_find_safe(search_start, remaining, api_name, name_len);
            if (!found) break;
            g_string_matches[g_string_match_count].addr = found;
            g_string_matches[g_string_match_count].api_name = api_name;
            g_string_matches[g_string_match_count].api_index = api_idx;
            g_string_match_count++;
            LOGI("[scan] Found string '%s' @ 0x%" PRIxPTR " in region %s",
                 api_name, found, region->path[0] ? region->path : "[anon]");
            size_t offset = found - search_start + name_len;
            search_start += offset;
            remaining -= offset;
        }
    }
}

// 步骤1: 扫描可读区域，查找 "il2cpp_xxx\0" 字符串
// 策略：先扫 .so 文件区域（快+无 SIGSEGV），再扫其他区域（仅在需要时）
static void scan_api_strings(void) {
    g_string_match_count = 0;
    install_sigsegv_handler();
    int scanned = 0;

    // === 第1轮：只扫 .so 文件区域（快速、安全）===
    for (int r = 0; r < g_region_count && g_string_match_count < MAX_API_STRINGS; r++) {
        MemRegion *region = &g_regions[r];
        size_t size = region->end - region->start;
        if (should_skip_region(region, size)) continue;
        // 第1轮只扫有 .so 路径的区域
        if (!strstr(region->path, ".so")) continue;
        scanned++;
        scan_region_for_strings(region);
    }
    LOGI("[scan] Phase 1 (.so regions): scanned %d, found %d strings", scanned, g_string_match_count);

    // 如果每个 API 至少有2个字符串匹配，足够用于 pair 解析，跳过慢速扫描
    if (all_apis_have_strings(2)) {
        LOGI("[scan] All APIs have enough strings, skipping phase 2");
        uninstall_sigsegv_handler();
        return;
    }

    // === 第2轮：扫描剩余区域（包括匿名区域，用于找 MHP 的字符串副本）===
    int phase2 = 0;
    for (int r = 0; r < g_region_count && g_string_match_count < MAX_API_STRINGS; r++) {
        MemRegion *region = &g_regions[r];
        size_t size = region->end - region->start;
        if (should_skip_region(region, size)) continue;
        if (strstr(region->path, ".so")) continue; // 第1轮已扫
        // 匿名区域只扫 <10MB 的（减少 SIGSEGV）
        if (region->path[0] == '\0' && size > 10 * 1024 * 1024) continue;
        scanned++; phase2++;
        scan_region_for_strings(region);
        // 每个 API 至少 2 个匹配就够了
        if (all_apis_have_strings(2)) {
            LOGI("[scan] All APIs found, stopping early at phase 2 region %d", phase2);
            break;
        }
    }
    LOGI("[scan] Phase 2: scanned %d more, total %d strings", phase2, g_string_match_count);

    LOGI("[scan] Total: scanned %d readable regions, found %d API string occurrences", scanned, g_string_match_count);
    uninstall_sigsegv_handler();
}

// 步骤2: 在 rw- 区域查找 {string_ptr, func_ptr} 配对
static int resolve_apis_from_pairs(void) {
    int resolved = 0;
    int scanned_pair_regions = 0;

    // 分两轮：第一轮只接受 offset+1，第二轮尝试 offset+2
    // 确保同一张表的 API 优先（正确的表通常都是 offset+1）
    for (int target_off = 1; target_off <= 2 && resolved < API_COUNT; target_off++) {
    
    for (int r = 0; r < g_region_count; r++) {
        MemRegion *region = &g_regions[r];
        // 必须 rw-（非可执行）
        if (!region->readable || !region->writable || region->executable) continue;

        size_t size = region->end - region->start;
        if (size < 16 || size > MAX_SCAN_SIZE) continue;

        // 跳过不可能包含 API 配对的区域
        if (strstr(region->path, "/dev/")) continue;
        if (strstr(region->path, "dalvik")) continue;
        if (strstr(region->path, "/dmabuf") || strstr(region->path, "/gpu") ||
            strstr(region->path, "kgsl") || strstr(region->path, "mali")) continue;
        // 跳过太大的匿名区域（>50MB）
        if (region->path[0] == '\0' && size > 50 * 1024 * 1024) continue;

        if (target_off == 1) scanned_pair_regions++;

        install_sigsegv_handler();

        // 遍历每个指针大小的对齐位置
        uintptr_t scan_end = region->end - 4 * sizeof(void*); // 留足空间读后续指针
        for (uintptr_t addr = region->start; addr <= scan_end; addr += sizeof(void*)) {
            // 安全读取：如果 SIGSEGV 则跳过整个区域
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) {
                g_in_safe_access = 0;
                if (target_off == 1) {
                    LOGW("[scan] SIGSEGV in resolve_apis_from_pairs at region 0x%" PRIxPTR, region->start);
                }
                break; // 跳出 for 循环，跳到下一个区域
            }
            uintptr_t val1 = *(volatile uintptr_t *)addr;          // 可能是 string_ptr
            g_in_safe_access = 0;

            // 快速过滤
            if (val1 < 0x1000) continue;

            // 检查 val1 是否匹配我们找到的某个 API 字符串地址
            for (int s = 0; s < g_string_match_count; s++) {
                if (val1 == g_string_matches[s].addr) {
                    int api_idx = g_string_matches[s].api_index;
                    
                    // 检查这个 API 是否已经解析过
                    if (*g_api_table[api_idx].func_ptr != NULL) continue;

                    // 只尝试当前轮次的偏移
                    {
                        int off = target_off;
                        g_in_safe_access = 1;
                        if (sigsetjmp(g_jmpbuf, 1) != 0) {
                            g_in_safe_access = 0;
                            break;
                        }
                        uintptr_t candidate = *(volatile uintptr_t *)(addr + off * sizeof(void*));
                        g_in_safe_access = 0;

                        if (candidate < 0x10000) continue;
                        // ARM64: 函数地址必须 4 字节对齐
                        if (candidate % 4 != 0) continue;
                        // 跳过指向字符串自身的指针
                        if (candidate == val1) continue;

                        // 排除已知的 API 字符串地址（避免误将下一个 name_ptr 当作 func_ptr）
                        int is_known_string = 0;
                        for (int ks = 0; ks < g_string_match_count; ks++) {
                            if (candidate == g_string_matches[ks].addr) {
                                is_known_string = 1;
                                break;
                            }
                        }
                        if (is_known_string) continue;

                        // 验证函数指针指向可执行的内存区域（r-x 或 rwx）
                        int valid_ptr = 0;
                        for (int c = 0; c < g_region_count; c++) {
                            if (candidate >= g_regions[c].start && candidate < g_regions[c].end) {
                                if (g_regions[c].executable) {
                                    valid_ptr = 1;
                                }
                                break;
                            }
                        }

                        if (valid_ptr) {
                            *g_api_table[api_idx].func_ptr = (void *)candidate;
                            g_pair_addrs[api_idx] = addr;
                            resolved++;
                            LOGI("[scan] Resolved %s @ 0x%" PRIxPTR " (string @ 0x%" PRIxPTR ", pair @ 0x%" PRIxPTR ", offset +%d)",
                                 g_api_table[api_idx].name, candidate, val1, addr, off);
                        }
                    }
                }
            }

            // 所有 API 都解析完成
            if (resolved >= API_COUNT) goto done;
        }
    }
    
    if (target_off == 1) {
        LOGI("[scan] Pass 1 (offset+1): resolved %d/%d APIs", resolved, API_COUNT);
    }
    
    } // end target_off loop

done:
    uninstall_sigsegv_handler();
    LOGI("[scan] Scanned %d rw- regions for pairs, resolved %d/%d APIs", scanned_pair_regions, resolved, API_COUNT);
    // 至少需要前6个核心 API（domain_get, thread_attach, domain_get_assemblies, 
    // assembly_get_image, image_get_name, class_from_name）
    if (resolved >= 6) {
        if (resolved < API_COUNT) {
            LOGW("[scan] Only %d/%d APIs resolved, some features may be limited", resolved, API_COUNT);
        }
        return 0;
    }
    return -1;
}

// ========== il2cpp 运行时上下文（初始化后全局缓存）==========
static Il2CppDomain  g_domain       = NULL;
static Il2CppImage   g_csharp_image = NULL;
static Il2CppClass   g_roleinfo_cls = NULL;
static Il2CppClass   g_warinfo_cls  = NULL;  // RoleInfoToWar

// 初始化 il2cpp 上下文（domain / image / class），只需调用一次
// 注意：在 APK 重打包模式下，libgoldhack.so 在 attachBaseContext 中加载，
// 此时 il2cpp 可能尚未完全初始化（GC 子系统等），需要等待并重试。
static int init_il2cpp_context(void) {
    if (g_roleinfo_cls) return 0;  // 已初始化

    // 等待 il2cpp 完全初始化：尝试调用 domain_get，如果返回 NULL 或
    // thread_attach 崩溃（通过 signal handler 捕获），则等待重试
    int max_retries = 30;  // 最多等待 30 秒
    for (int attempt = 0; attempt < max_retries; attempt++) {
        LOGI("Calling il2cpp_domain_get @ %p (attempt %d/%d)", 
             (void*)fn_domain_get, attempt + 1, max_retries);
        g_domain = fn_domain_get();
        if (g_domain) {
            // domain_get 成功，再尝试 thread_attach
            // 先检查 il2cpp 内部 GC 是否就绪：domain_get_assemblies 需要 GC
            // 如果 assemblies 返回非空且 count > 0，说明 il2cpp 已完全初始化
            size_t test_count = 0;
            Il2CppAssembly *test_assemblies = fn_domain_get_assemblies(g_domain, &test_count);
            if (test_assemblies && test_count > 0) {
                LOGI("Domain: %p, assemblies: %zu, il2cpp is fully initialized", 
                     g_domain, test_count);
                break;
            }
            LOGW("Domain: %p but assemblies not ready (count=%zu), waiting 1s...", 
                 g_domain, test_count);
        } else {
            LOGW("il2cpp_domain_get returned NULL, waiting 1s...");
        }
        g_domain = NULL;
        sleep(1);
    }
    if (!g_domain) { LOGE("il2cpp_domain_get failed after %d attempts", max_retries); return -1; }

    LOGI("Calling thread_attach...");
    fn_thread_attach(g_domain);
    LOGI("Attached to il2cpp domain");

    // HybridCLR 游戏: Assembly-CSharp.dll 不在静态 assembly 列表中，
    // 而是由 HybridCLR 在运行时动态加载。需要轮询等待它出现。
    int asm_max_wait = 60;  // 最多等待 60 秒（HybridCLR 加载热更新 DLL 需要时间）
    for (int asm_attempt = 0; asm_attempt < asm_max_wait; asm_attempt++) {
        size_t asm_count = 0;
        Il2CppAssembly *assemblies = fn_domain_get_assemblies(g_domain, &asm_count);
        if (!assemblies || asm_count == 0) {
            LOGW("No assemblies found (attempt %d/%d), waiting 1s...", 
                 asm_attempt + 1, asm_max_wait);
            sleep(1);
            continue;
        }

        // 每隔 10 次打印一次完整 assembly 列表（调试用）
        if (asm_attempt == 0 || asm_attempt % 10 == 0) {
            LOGI("Assembly list (attempt %d, count=%zu):", asm_attempt + 1, asm_count);
            for (size_t i = 0; i < asm_count; i++) {
                Il2CppAssembly a = ((Il2CppAssembly *)assemblies)[i];
                Il2CppImage img = fn_assembly_get_image(a);
                const char *n = img ? fn_image_get_name(img) : "(null)";
                LOGI("  [%zu] %s", i, n ? n : "(null)");
            }
        }

        // 查找 Assembly-CSharp.dll
        for (size_t i = 0; i < asm_count; i++) {
            Il2CppAssembly asm_ptr = ((Il2CppAssembly *)assemblies)[i];
            Il2CppImage img = fn_assembly_get_image(asm_ptr);
            if (!img) continue;
            const char *name = fn_image_get_name(img);
            if (name && strcmp(name, "Assembly-CSharp.dll") == 0) {
                g_csharp_image = img;
                break;
            }
        }
        if (g_csharp_image) {
            LOGI("Found Assembly-CSharp.dll: %p (after %d attempts, total assemblies: %zu)", 
                 g_csharp_image, asm_attempt + 1, asm_count);
            break;
        }

        if (asm_attempt == 0) {
            LOGI("Assembly-CSharp.dll not yet loaded (HybridCLR), waiting for dynamic load... "
                 "(found %zu static assemblies)", asm_count);
        }
        sleep(1);
    }
    if (!g_csharp_image) { 
        LOGE("Assembly-CSharp.dll not found after %d seconds (HybridCLR may have failed to load it)", 
             asm_max_wait); 
        return -1; 
    }

    g_roleinfo_cls = fn_class_from_name(g_csharp_image, "", "RoleInfo");
    if (!g_roleinfo_cls) { LOGE("RoleInfo class not found"); return -1; }
    LOGI("RoleInfo klass: %p", g_roleinfo_cls);

    g_warinfo_cls = fn_class_from_name(g_csharp_image, "", "RoleInfoToWar");
    if (g_warinfo_cls) {
        LOGI("RoleInfoToWar klass: %p", g_warinfo_cls);
    } else {
        LOGW("RoleInfoToWar class not found (non-fatal)");
    }
    return 0;
}

// ========== 枚举游戏类方法/字段（用于分析更新和登录机制）==========
static void log_class_info(const char *name, const char *ns) {
    Il2CppClass klass = fn_class_from_name(g_csharp_image, ns, name);
    if (!klass) {
        LOGW("[enum] Class '%s%s%s' not found", ns[0] ? ns : "", ns[0] ? "." : "", name);
        return;
    }
    LOGI("[enum] === %s%s%s @ %p ===", ns[0] ? ns : "", ns[0] ? "." : "", name, klass);
    
    // 枚举方法
    if (fn_class_get_methods && fn_method_get_name) {
        void *iter = NULL;
        Il2CppMethodInfo method;
        while ((method = fn_class_get_methods(klass, &iter)) != NULL) {
            const char *mname = fn_method_get_name(method);
            int pcount = fn_method_get_param_count ? fn_method_get_param_count(method) : -1;
            LOGI("[enum]   M: %s(%d) @%p", mname ? mname : "?", pcount, method);
        }
    }
    
    // 枚举字段
    if (fn_class_get_fields && fn_field_get_name) {
        void *fiter = NULL;
        Il2CppFieldInfo field;
        while ((field = fn_class_get_fields(klass, &fiter)) != NULL) {
            const char *fname = fn_field_get_name(field);
            int offset = fn_field_get_offset ? fn_field_get_offset(field) : -1;
            LOGI("[enum]   F: %s (offset=%d)", fname ? fname : "?", offset);
        }
    }
}

static void enumerate_game_classes(void) {
    LOGI("[enum] ========== Enumerating game classes ==========");
    
    // 更新/版本检查相关
    log_class_info("PackageVersionControl", "");
    log_class_info("PackageStateInit", "");
    log_class_info("PackageStateUpdateVersion", "");
    log_class_info("PackageDownloadPanel", "");
    log_class_info("GameStartPanel", "");
    log_class_info("FsmInitBootPackage", "");
    log_class_info("VersionCheckResult", "");
    log_class_info("ConfigManager", "");
    log_class_info("GameManager", "");
    
    // 登录相关
    log_class_info("LoginGuanFangPanel", "");
    log_class_info("LoginPanel", "");
    log_class_info("SDKManager", "");
    
    // 职业/角色解锁相关
    log_class_info("UserInfo", "");
    log_class_info("PurchaseManager", "");
    log_class_info("Achieve", "");
    log_class_info("ProtoLogin", "");
    log_class_info("BookShelfManager", "");
    log_class_info("EnterLayer", "");
    log_class_info("GameStartCheck", "");
    
    LOGI("[enum] ========== Enumeration complete ==========");
}

// ========== il2cpp MethodInfo hook 工具 ==========
// HybridCLR 方法的 methodPointer (field[0]) 是共享的解释器蹦床，
// 不能直接 inline hook。正确做法：直接替换 MethodInfo->methodPointer 为我们的函数。
// 这样 il2cpp 调用该方法时会执行我们的替代函数。

// 替换 MethodInfo 中的 methodPointer (offset 0) 为自定义函数
// 返回旧的 methodPointer（可用于后续调用原始方法）
static uintptr_t replace_method_pointer(Il2CppMethodInfo method, void *new_func, const char *name) {
    if (!method || !new_func) return 0;
    uintptr_t *fields = (uintptr_t *)method;
    uintptr_t old_ptr = fields[0];
    
    // MethodInfo 在堆中，通常已有写权限，但为保险起见 mprotect
    uintptr_t page = (uintptr_t)method & ~(uintptr_t)0xFFF;
    mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE);
    
    fields[0] = (uintptr_t)new_func;
    
    LOGI("[hook] %s: MethodInfo %p, old methodPtr=%p -> new=%p",
         name, method, (void*)old_ptr, new_func);
    return old_ptr;
}

// 使用 inline hook 替换函数入口（仅用于 AOT 方法或 libc 函数）
// 将 target_func 的前 16 字节替换为跳转到 hook_func 的指令
static int inline_hook_method(uintptr_t target_func, void *hook_func, const char *name) {
    if (!target_func || !hook_func) return -1;
    
    uintptr_t page = target_func & ~(uintptr_t)0xFFF;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("[hook] mprotect RWX failed for %s @ %p: %s", name, (void*)target_func, strerror(errno));
        if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
            LOGE("[hook] mprotect RW also failed for %s", name);
            return -1;
        }
    }
    
    // LDR X16, [PC, #8] + BR X16 + .quad addr
    uint32_t *code = (uint32_t *)target_func;
    code[0] = 0x58000050;  // LDR X16, [PC, #8]
    code[1] = 0xD61F0200;  // BR X16
    uint64_t *target = (uint64_t *)(code + 2);
    *target = (uint64_t)hook_func;
    
    __builtin___clear_cache((char *)target_func, (char *)(target_func + 16));
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    
    LOGI("[hook] %s @ %p -> %p (inline hook installed)", name, (void*)target_func, hook_func);
    return 0;
}

// ========== 版本检查绕过 ==========
// HybridCLR 方法: 通过替换 MethodInfo.methodPointer 来拦截
// il2cpp 调用约定: (void* thisptr, Il2CppMethodInfo method, ...)

// Hook PackageVersionControl.get_IsOn() -> 返回 false（关闭版本检查）
static void* hook_pvc_get_IsOn(void *thisptr, Il2CppMethodInfo method) {
    (void)thisptr; (void)method;
    LOGI("[bypass] PVC.get_IsOn -> false");
    return (void*)0; // false - 关闭版本检查
}

// Hook PackageVersionControl.CheckForceUpgrade() -> 返回 false
static void* hook_pvc_CheckForceUpgrade(void *thisptr, Il2CppMethodInfo method) {
    (void)thisptr; (void)method;
    LOGI("[bypass] CheckForceUpgrade -> false");
    return (void*)0; // 不需要强制更新
}

// Hook PackageVersionControl.DealCheckResult(VersionCheckResult) -> 什么都不做
static void* hook_pvc_DealCheckResult(void *thisptr, Il2CppMethodInfo method, void *result) {
    (void)thisptr; (void)method; (void)result;
    LOGI("[bypass] DealCheckResult blocked");
    return (void*)0;
}

// Hook PackageVersionControl.CheckComplete(bool) -> 直接返回
static void* hook_pvc_CheckComplete(void *thisptr, Il2CppMethodInfo method, int result) {
    (void)thisptr; (void)method; (void)result;
    LOGI("[bypass] CheckComplete blocked");
    return (void*)0;
}

// Hook PackageStateInit.CheckUpdateVersion -> 跳过版本检查
static void* hook_psi_CheckUpdateVersion(void *thisptr, Il2CppMethodInfo method, void *arg1, void *arg2) {
    (void)thisptr; (void)method; (void)arg1; (void)arg2;
    LOGI("[bypass] PackageStateInit.CheckUpdateVersion blocked");
    return (void*)0;
}

static int bypass_version_check(void) {
    LOGI("[bypass] ===== Installing version check bypass =====");
    int hooked = 0;
    
    Il2CppClass pvc_class = fn_class_from_name(g_csharp_image, "", "PackageVersionControl");
    if (!pvc_class) {
        LOGW("[bypass] PackageVersionControl class not found, skipping version bypass");
        return 0;
    }
    
    if (fn_class_get_method_from_name) {
        Il2CppMethodInfo m;
        
        // Hook get_IsOn() - 关闭版本检查开关
        m = fn_class_get_method_from_name(pvc_class, "get_IsOn", 0);
        if (m) { replace_method_pointer(m, (void*)hook_pvc_get_IsOn, "PVC.get_IsOn"); hooked++; }
        
        // Hook CheckForceUpgrade()
        m = fn_class_get_method_from_name(pvc_class, "CheckForceUpgrade", 0);
        if (m) { replace_method_pointer(m, (void*)hook_pvc_CheckForceUpgrade, "PVC.CheckForceUpgrade"); hooked++; }
        
        // Hook DealCheckResult(1)
        m = fn_class_get_method_from_name(pvc_class, "DealCheckResult", 1);
        if (m) { replace_method_pointer(m, (void*)hook_pvc_DealCheckResult, "PVC.DealCheckResult"); hooked++; }
        
        // Hook CheckComplete(1)
        m = fn_class_get_method_from_name(pvc_class, "CheckComplete", 1);
        if (m) { replace_method_pointer(m, (void*)hook_pvc_CheckComplete, "PVC.CheckComplete"); hooked++; }
    }
    
    // 也 hook PackageStateInit.CheckUpdateVersion
    Il2CppClass psi_class = fn_class_from_name(g_csharp_image, "", "PackageStateInit");
    if (psi_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m = fn_class_get_method_from_name(psi_class, "CheckUpdateVersion", 2);
        if (m) { replace_method_pointer(m, (void*)hook_psi_CheckUpdateVersion, "PSI.CheckUpdateVersion"); hooked++; }
    }
    
    LOGI("[bypass] Version check bypass: %d hooks installed", hooked);
    return hooked;
}

// ========== DLC/职业解锁绕过 ==========
// HybridCLR il2cpp 调用约定: (void* thisptr, Il2CppMethodInfo method, ...)

// Hook UserInfo.IsDLCRole(int roleId) -> 返回 false（所有角色都不是 DLC，可免费选择）
static void* hook_userinfo_IsDLCRole(void *thisptr, Il2CppMethodInfo method, int roleId) {
    (void)thisptr; (void)method;
    LOGI("[bypass] IsDLCRole(%d) -> false (unlocked)", roleId);
    return (void*)0; // false = 不是 DLC 角色 = 免费可用
}

// Hook UserInfo.IsBaseRole(int roleId) -> 返回 true（所有角色都是基础角色）
static void* hook_userinfo_IsBaseRole(void *thisptr, Il2CppMethodInfo method, int roleId) {
    (void)thisptr; (void)method;
    LOGI("[bypass] IsBaseRole(%d) -> true", roleId);
    return (void*)1; // true = 基础角色 = 不需要购买
}

// Hook PurchaseManager.IsUnlockShop_PVP(int shopId) -> 返回 true
static void* hook_pm_IsUnlockShop_PVP(void *thisptr, Il2CppMethodInfo method, int shopId) {
    (void)thisptr; (void)method;
    LOGI("[bypass] IsUnlockShop_PVP(%d) -> true", shopId);
    return (void*)1; // 已解锁
}

// Hook SDKManager.IsFroceLogin() -> 返回 false（不强制登录）
static void* hook_sdk_IsForceLogin(void *thisptr, Il2CppMethodInfo method) {
    (void)thisptr; (void)method;
    LOGI("[bypass] IsFroceLogin -> false");
    return (void*)0; // false = 不需要强制登录
}

// Hook PurchaseManager.IsNeedBind() -> 返回 false（不需要绑定）
static void* hook_pm_IsNeedBind(void *thisptr, Il2CppMethodInfo method) {
    (void)thisptr; (void)method;
    LOGI("[bypass] IsNeedBind -> false");
    return (void*)0; // false = 不需要绑定
}

// Hook ProtoLogin.IsDLCRole(int) -> 返回 false
static void* hook_proto_IsDLCRole(void *thisptr, Il2CppMethodInfo method, int roleId) {
    (void)thisptr; (void)method;
    LOGI("[bypass] ProtoLogin.IsDLCRole(%d) -> false", roleId);
    return (void*)0;
}

// Hook ProtoLogin.IsUnlockAllDLC(int) -> 返回 true
static void* hook_proto_IsUnlockAllDLC(void *thisptr, Il2CppMethodInfo method, int arg) {
    (void)thisptr; (void)method; (void)arg;
    LOGI("[bypass] ProtoLogin.IsUnlockAllDLC -> true");
    return (void*)1;
}

// Hook Achieve.checkDLCUnlock(GameItemID, AchievementType) -> 返回 true
static void* hook_achieve_checkDLCUnlock(void *thisptr, Il2CppMethodInfo method, int gameItemId, int achieveType) {
    (void)thisptr; (void)method;
    LOGI("[bypass] Achieve.checkDLCUnlock(%d, %d) -> true", gameItemId, achieveType);
    return (void*)1; // 已解锁
}

// Hook EnterLayer.CheckLogin() -> 跳过登录检查
static void* hook_enterlayer_CheckLogin(void *thisptr, Il2CppMethodInfo method) {
    (void)thisptr; (void)method;
    LOGI("[bypass] EnterLayer.CheckLogin -> skip");
    return (void*)0;
}

// Hook GameStartCheck.CheckForceUpgrade(int) -> 返回 false
static void* hook_gsc_CheckForceUpgrade(void *thisptr, Il2CppMethodInfo method, int arg) {
    (void)thisptr; (void)method; (void)arg;
    LOGI("[bypass] GameStartCheck.CheckForceUpgrade -> false");
    return (void*)0;
}

static int bypass_dlc_lock(void) {
    LOGI("[bypass] ===== Installing DLC/career unlock bypass =====");
    int hooked = 0;
    
    // Hook UserInfo.IsDLCRole -> false, IsBaseRole -> true
    Il2CppClass ui_class = fn_class_from_name(g_csharp_image, "", "UserInfo");
    if (ui_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m;
        m = fn_class_get_method_from_name(ui_class, "IsDLCRole", 1);
        if (m) { replace_method_pointer(m, (void*)hook_userinfo_IsDLCRole, "UserInfo.IsDLCRole"); hooked++; }
        
        m = fn_class_get_method_from_name(ui_class, "IsBaseRole", 1);
        if (m) { replace_method_pointer(m, (void*)hook_userinfo_IsBaseRole, "UserInfo.IsBaseRole"); hooked++; }
    }
    
    // Hook PurchaseManager
    Il2CppClass pm_class = fn_class_from_name(g_csharp_image, "", "PurchaseManager");
    if (pm_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m;
        m = fn_class_get_method_from_name(pm_class, "IsUnlockShop_PVP", 1);
        if (m) { replace_method_pointer(m, (void*)hook_pm_IsUnlockShop_PVP, "PM.IsUnlockShop_PVP"); hooked++; }
        
        m = fn_class_get_method_from_name(pm_class, "IsNeedBind", 0);
        if (m) { replace_method_pointer(m, (void*)hook_pm_IsNeedBind, "PM.IsNeedBind"); hooked++; }
    }
    
    // Hook SDKManager.IsFroceLogin -> false
    Il2CppClass sdk_class = fn_class_from_name(g_csharp_image, "", "SDKManager");
    if (sdk_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m = fn_class_get_method_from_name(sdk_class, "IsFroceLogin", 0);
        if (m) { replace_method_pointer(m, (void*)hook_sdk_IsForceLogin, "SDK.IsFroceLogin"); hooked++; }
    }
    
    // Hook ProtoLogin.IsDLCRole, IsUnlockAllDLC
    Il2CppClass proto_class = fn_class_from_name(g_csharp_image, "", "ProtoLogin");
    if (proto_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m;
        m = fn_class_get_method_from_name(proto_class, "IsDLCRole", 1);
        if (m) { replace_method_pointer(m, (void*)hook_proto_IsDLCRole, "ProtoLogin.IsDLCRole"); hooked++; }
        
        m = fn_class_get_method_from_name(proto_class, "IsUnlockAllDLC", 1);
        if (m) { replace_method_pointer(m, (void*)hook_proto_IsUnlockAllDLC, "ProtoLogin.IsUnlockAllDLC"); hooked++; }
    }
    
    // Hook Achieve.checkDLCUnlock
    Il2CppClass achieve_class = fn_class_from_name(g_csharp_image, "", "Achieve");
    if (achieve_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m = fn_class_get_method_from_name(achieve_class, "checkDLCUnlock", 2);
        if (m) { replace_method_pointer(m, (void*)hook_achieve_checkDLCUnlock, "Achieve.checkDLCUnlock"); hooked++; }
    }
    
    // Hook EnterLayer.CheckLogin
    Il2CppClass enter_class = fn_class_from_name(g_csharp_image, "", "EnterLayer");
    if (enter_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m = fn_class_get_method_from_name(enter_class, "CheckLogin", 0);
        if (m) { replace_method_pointer(m, (void*)hook_enterlayer_CheckLogin, "EnterLayer.CheckLogin"); hooked++; }
    }
    
    // Hook GameStartCheck.CheckForceUpgrade
    Il2CppClass gsc_class = fn_class_from_name(g_csharp_image, "", "GameStartCheck");
    if (gsc_class && fn_class_get_method_from_name) {
        Il2CppMethodInfo m = fn_class_get_method_from_name(gsc_class, "CheckForceUpgrade", 1);
        if (m) { replace_method_pointer(m, (void*)hook_gsc_CheckForceUpgrade, "GSC.CheckForceUpgrade"); hooked++; }
    }
    
    LOGI("[bypass] DLC/career unlock bypass: %d hooks installed", hooked);
    return hooked;
}

// ========== DLC 解锁 - 自定义 C invoker 方案 ==========
// HybridCLR 解释器的 invoker 忽略 methodPointer，直接通过 interpData 执行 IL 字节码。
// 方案 v5: 写自定义 C invoker 函数，直接返回 boxed true，完全绕过 HybridCLR 解释器。
// il2cpp_runtime_invoke 调用 invoker(methodPtr, method, obj, params, exc)
// 我们的 invoker 忽略所有参数，创建 boxed Boolean(true) 并返回。
static Il2CppClass   g_proto_login_cls  = NULL;
static uintptr_t     g_proto_login_inst = 0;
static Il2CppClass   g_boolean_class    = NULL;
static volatile int  g_verification_complete = 0;  // v6.7: 验证完成后设为1，用于追踪解释器调用

// ===== ARM64 可执行 stub（分配后长期存活）=====
// 用于替换 HybridCLR 方法的 methodPointer
static void *g_stub_return_true = NULL;   // bool return true stub
static void *g_stub_invoker_true = NULL;  // invoker wrapper stub (unused now)

// ===== 自定义 methodPointer 替代函数 =====
// 用于替换 HybridCLR 方法的 methodPointer (field[0])
// 签名: bool Method(void* this, int32_t arg, MethodInfo* method)
// 在 ARM64 上, 多余参数在寄存器中传递,无害地被忽略
static uint8_t custom_return_true_method(void* __this, int32_t arg1, void* arg2, void* method) {
    // v6.7: 追踪是否有解释器在调用我们的补丁函数
    if (g_verification_complete) {
        static int post_calls = 0;
        if (post_calls < 30) {
            LOGI("[intercept] custom_return_true CALLED post-verify! this=%p arg=%d method=%p #%d",
                 __this, arg1, method, post_calls);
            post_calls++;
        }
    }
    return 1;
}

// ===== 自定义 C invoker =====
// ===== Unity 2020 invoker 签名 (4 参数!) =====
// Unity 2020 invoker: Il2CppObject* invoker(Il2CppMethodPointer methodPtr, const MethodInfo* method, void* obj, void** params)
// 注意: Unity 2020 invoker 返回 Il2CppObject*! 不是 void!
// 与 Unity 2021+ 不同, Unity 2020 没有 ret 参数!
// invoker 负责调用 methodPtr, Box 返回值, 并返回 boxed 对象.
static void* custom_bool_true_invoker(void* methodPtr, void* method, void* obj, void** params) {
    // 创建 boxed Boolean(true)
    // Il2CppObject = [klass(8)][monitor(8)][data...], bool 数据在 +0x10
    LOGI("[invoker] custom_bool_true_invoker called! methodPtr=%p method=%p obj=%p", methodPtr, method, obj);
    if (fn_object_new && g_boolean_class) {
        void* boxed = fn_object_new(g_boolean_class);
        if (boxed) {
            *(uint8_t *)((uint8_t *)boxed + 0x10) = 1;  // true
            LOGI("[invoker] created boxed Boolean(true) @ %p", boxed);
            return boxed;
        }
    }
    // fallback: 如果无法创建 boxed 对象, 直接返回 (void*)1
    // 这在 il2cpp_runtime_invoke 中会 SIGSEGV, 但至少不会 NULL
    LOGW("[invoker] WARNING: Cannot create boxed Boolean! fn_object_new=%p g_boolean_class=%p", fn_object_new, g_boolean_class);
    return (void*)(uintptr_t)1;
}

// ===== v6.5: void NOP method — 替换 void 方法让其什么都不做 =====
// 签名: void Method(void* this, MethodInfo* method) 
// ARM64 会忽略多余参数
static void custom_void_nop_method(void* __this, void* method) {
    (void)__this; (void)method;
    // do nothing — NOP
}

// ===== v6.5: void NOP invoker — Unity 2020: 4 params, return NULL =====
static void* custom_void_nop_invoker(void* methodPtr, void* method, void* obj, void** params) {
    (void)methodPtr; (void)method; (void)obj; (void)params;
    return NULL;  // void 方法返回 NULL
}

// ===== v6.5: bool return false method — 返回 false =====
static uint8_t custom_return_false_method(void* __this, int32_t arg1, void* arg2, void* method) {
    (void)__this; (void)arg1; (void)arg2; (void)method;
    return 0;
}

// ===== v6.5: bool false invoker — Unity 2020: 4 params, return boxed false =====
static void* custom_bool_false_invoker(void* methodPtr, void* method, void* obj, void** params) {
    if (fn_object_new && g_boolean_class) {
        void* boxed = fn_object_new(g_boolean_class);
        if (boxed) {
            *(uint8_t *)((uint8_t *)boxed + 0x10) = 0;  // false
            return boxed;
        }
    }
    return NULL;
}

// ===== v6.20: HybridCLR interpreter bridge — 返回 bool true =====
// HybridCLR 解释器内部调用方法时使用 methodPointerCallByInterp (f[11]),
// 签名为: void (*)(const MethodInfo* method, uint16_t* argVarIndexs, StackObject* localVarBase, void* ret)
// StackObject 是 union { int64_t i64; ... }, 写 *(int64_t*)ret = 1 即 bool true
// 这解决了 v6.10/v6.19 的问题: il2cpp_runtime_invoke 走 invoker(f[1]) 能返回 true,
// 但 HybridCLR 解释器内部调用走 f[11](旧的解释器蹦床) 读到 interpData=NULL 返回 false
static void custom_hybridclr_bridge_bool_true(void* method, void* argVarIndexs, void* localVarBase, void* ret) {
    (void)method; (void)argVarIndexs; (void)localVarBase;
    if (ret) {
        *(int64_t*)ret = 1;  // StackObject.i64 = 1 (bool true)
    }
    static int call_count = 0;
    if (call_count < 20) {
        LOGI("[bridge] custom_hybridclr_bridge_bool_true called #%d method=%p ret=%p", call_count, method, ret);
        call_count++;
    }
}

// ===== v6.32: Interpreter::Execute inline hook =====
// 核心洞察: MI field patches (f[0], f[1], f[11], f[12]) 只影响 AOT→interp 调用路径.
// 解释器内部的 interp→interp 调用 (CallInterp_void IR 指令) 直接调用
// Interpreter::Execute(MethodInfo*, StackObject*, void* ret), 完全绕过 MI 的函数指针字段.
// 唯一的解决方案: hook Interpreter::Execute 本身.
//
// Execute 签名: static void Execute(const MethodInfo* methodInfo, StackObject* args, void* ret)
// ARM64 ABI: X0=methodInfo, X1=args, X2=ret
//
// Hook 策略:
// 1. 从桥接函数 (所有 HybridCLR 方法共享的 methodPointer) 反汇编找到 Execute 的 BL 调用
// 2. 在 Execute 入口安装 inline hook, 跳转到我们的 trampoline
// 3. Trampoline: 检查 X0 是否在目标 MI 列表中
//    - 匹配: 向 [X2] 写入 1 (bool true) 并返回
//    - 不匹配: 跳转到 trampoline 执行原始指令, 然后跳回 Execute+16

// 目标 MethodInfo 列表 (运行时填充)
#define MAX_EXECUTE_HOOK_TARGETS 64
static uintptr_t g_execute_hook_targets[MAX_EXECUTE_HOOK_TARGETS];
static int g_execute_hook_target_count = 0;
static volatile int g_execute_hook_installed = 0;

// v6.34: interpData 二级索引 — 捕获同一方法的不同 MI 对象
static uintptr_t g_execute_hook_interp_targets[MAX_EXECUTE_HOOK_TARGETS];
static int g_execute_hook_interp_count = 0;

// v6.34: 诊断计数器
static volatile int g_execute_total_calls = 0;
static volatile int g_execute_intercepted_calls = 0;
static volatile int g_execute_early_intercepts = 0;

// v6.35: Execute hook 旁路标志 (REAL verification 期间设为 1, 跳过所有拦截)
static volatile int g_execute_hook_bypass = 0;

// v6.34: 方法名匹配列表 (用于早期拦截, 在 MI 目标注册前生效)
// 这些是 DLC 相关的方法名, 在 Execute hook 中按名称匹配
static const char *g_early_match_names[] = {
    "isUnlockRole", "IsDLCRole", "IsUnlockAllDLC",
    "IsUnlockByFirstGame", "IsUnlockGuBao",
    "IsDianCang", "IsOldPlayer", "isUnlockDLC",
    "IsBoughtAllItems", "IsUnlockByGameId", "IsUnlockByGameIds",
    "isUnlockByItem",
    "get_isUnlockAll", "IsUnlockDianCang",
    "IsUnlockAll", "IsUnlockByExtra", "IsUnlockAnyDlc", "isUnlock",
    NULL
};

// v6.34: 缓存 libil2cpp.so 基址 (用于缓存 Execute 偏移)
static uintptr_t g_il2cpp_base_for_cache = 0;

// Execute 原始入口地址 (被 hook 后用于 trampoline)
static uintptr_t g_execute_addr = 0;
// 保存的原始指令 (前 16 字节 = 4 条 ARM64 指令)
static uint32_t g_execute_saved_insns[4];
// Trampoline 地址
static void *g_execute_trampoline = NULL;

// 添加一个 MethodInfo 到 Execute hook 目标列表
static void execute_hook_add_target(void *mi) {
    if (!mi) return;
    // 去重
    for (int i = 0; i < g_execute_hook_target_count; i++) {
        if (g_execute_hook_targets[i] == (uintptr_t)mi) return;
    }
    if (g_execute_hook_target_count < MAX_EXECUTE_HOOK_TARGETS) {
        g_execute_hook_targets[g_execute_hook_target_count++] = (uintptr_t)mi;
        LOGI("[exec-hook] Added target MI=%p (#%d)", mi, g_execute_hook_target_count);
    }
    // v6.34: 同时记录 interpData (f[10]) 用于二级匹配
    uintptr_t *f = (uintptr_t *)mi;
    uintptr_t interp_data = f[10];
    if (interp_data && interp_data > 0x10000 && g_execute_hook_interp_count < MAX_EXECUTE_HOOK_TARGETS) {
        // 去重
        for (int i = 0; i < g_execute_hook_interp_count; i++) {
            if (g_execute_hook_interp_targets[i] == interp_data) return;
        }
        g_execute_hook_interp_targets[g_execute_hook_interp_count++] = interp_data;
        LOGI("[exec-hook] Added interpData target %p (#%d)", (void*)interp_data, g_execute_hook_interp_count);
    }
}

// 从 ARM64 BL 指令解码目标地址
// BL: 0x94000000 | (imm26)  或  BL: 0x97FFFFFF | ...
// imm26 是有符号偏移, 单位是 4 字节
static uintptr_t decode_bl_target(uintptr_t insn_addr) {
    uint32_t insn = *(uint32_t *)insn_addr;
    // BL 指令: opcode = 100101, 即 insn[31:26] == 0b100101
    if ((insn >> 26) != 0x25) return 0;  // 不是 BL
    // 提取 imm26 (有符号)
    int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
    // 符号扩展 26 位到 32 位
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000;
    // 目标地址 = insn_addr + imm26 * 4
    return insn_addr + (int64_t)imm26 * 4;
}

// 从桥接函数反汇编, 找到 Interpreter::Execute 的地址
// 桥接函数是所有 HybridCLR 方法共享的 methodPointer,
// 它内部会调用 Interpreter::Execute(method, args, ret)
// 我们查找前 128 字节内的 BL 指令
static uintptr_t find_execute_from_bridge(uintptr_t bridge_addr) {
    if (!bridge_addr) return 0;
    LOGI("[exec-hook] Scanning bridge function @ %p for BL to Execute...", (void*)bridge_addr);
    
    // 反汇编桥接函数的前 256 字节, 找所有 BL 指令
    // Execute 通常是桥接函数中最大的被调用函数
    uintptr_t bl_targets[16];
    int bl_count = 0;
    
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        LOGE("[exec-hook] SIGSEGV scanning bridge function");
        return 0;
    }
    
    for (int i = 0; i < 64 && bl_count < 16; i++) {  // 64 instructions = 256 bytes
        uintptr_t addr = bridge_addr + i * 4;
        uint32_t insn = *(volatile uint32_t *)addr;
        
        // 检查是否是 RET (0xD65F03C0)
        if (insn == 0xD65F03C0) {
            LOGI("[exec-hook] Hit RET at bridge+%d, stopping scan", i*4);
            break;
        }
        
        uintptr_t target = decode_bl_target(addr);
        if (target) {
            LOGI("[exec-hook] BL at bridge+0x%x -> %p", i*4, (void*)target);
            bl_targets[bl_count++] = target;
        }
    }
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    if (bl_count == 0) {
        LOGE("[exec-hook] No BL instructions found in bridge function");
        return 0;
    }
    
    // 启发式: Execute 通常是桥接函数中调用的最大函数
    // 我们可以通过检查每个 BL 目标函数的大小来判断
    // 更简单的方法: 桥接函数通常结构是:
    //   setup stack frame
    //   prepare args from MethodInfo
    //   BL Interpreter::Execute   ← 这是我们要找的
    //   cleanup and return
    // Execute 通常是桥接中唯一或最后一个 BL 调用
    // 使用最后一个 BL (在 RET 之前)
    uintptr_t execute_addr = bl_targets[bl_count - 1];
    
    // 但如果桥接函数很复杂, 可能有多个 BL
    // 验证: Execute 函数应该很大 (几千条指令)
    // 简单检查: 函数的前几条指令应该是标准的栈帧建立
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        // 检查目标函数的第一条指令
        uint32_t first_insn = *(volatile uint32_t *)execute_addr;
        // STP 指令 (栈帧建立) 通常以 0xA9 开头 (STP Xt, Xt, [SP, #imm]!)
        // 或 SUB SP, SP, #imm (0xD1)
        uint32_t opcode_hi = first_insn >> 24;
        LOGI("[exec-hook] Execute candidate @ %p, first insn=0x%08x (hi=0x%02x)",
             (void*)execute_addr, first_insn, opcode_hi);
    }
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    LOGI("[exec-hook] ★ Selected Execute @ %p (BL #%d of %d)", 
         (void*)execute_addr, bl_count, bl_count);
    return execute_addr;
}

// 安装 Execute inline hook 带 trampoline
// Trampoline 结构 (在 RWX 内存中):
//
// === entry point (from hook at Execute) ===
//   STP X0, X1, [SP, #-16]!    ; 保存 X0, X1
//   LDR X1, =target_list       ; 加载目标列表地址
//   LDR X16, =target_count     ; 加载目标数量地址
//   LDR W16, [X16]             ; 读取目标数量
// loop:
//   CBZ W16, not_found
//   LDR X17, [X1], #8          ; 读取下一个目标 MI
//   CMP X0, X17                ; 比较
//   B.EQ found
//   SUB W16, W16, #1
//   B loop
// not_found:
//   LDP X0, X1, [SP], #16      ; 恢复 X0, X1
//   <execute saved 4 instructions> ; 执行原始指令
//   LDR X16, =Execute+16       ; 跳回 Execute 继续
//   BR X16
// found:
//   LDP X0, X1, [SP], #16      ; 恢复 X0, X1
//   ; X2 = ret pointer (第三个参数, 未被修改)
//   MOV X16, #1
//   STR X16, [X2]              ; *(int64_t*)ret = 1 (bool true)
//   RET                        ; 直接返回, 不执行原始 Execute
//
// 但上面的纯汇编方式太复杂。改用 C 函数方式:
// trampoline 跳转到 C 函数, C 函数做判断, 然后调用原始 Execute 或直接返回。

// C hook 函数: 检查 MethodInfo 是否需要返回 true
// v6.34: 三层匹配:
//   1. MI 指针精确匹配 (最快)
//   2. interpData 匹配 (捕获同一方法的不同 MI 对象)
//   3. 方法名匹配 (早期模式, 在 MI 目标注册前生效)
typedef void (*execute_func_t)(const void* methodInfo, void* args, void* ret);
static execute_func_t g_orig_execute = NULL;  // 指向 trampoline (执行原始指令后跳回 Execute+16)

static void hook_execute_func(const void* methodInfo, void* args, void* ret) {
    int total = __atomic_add_fetch(&g_execute_total_calls, 1, __ATOMIC_RELAXED);
    
    // v6.35: 旁路模式 — REAL verification 期间跳过所有拦截
    if (__atomic_load_n(&g_execute_hook_bypass, __ATOMIC_ACQUIRE)) {
        g_orig_execute(methodInfo, args, ret);
        return;
    }
    
    uintptr_t mi_addr = (uintptr_t)methodInfo;
    const uintptr_t *f = (const uintptr_t *)methodInfo;
    
    // Phase 1: MI 指针精确匹配 (快速路径)
    for (int i = 0; i < g_execute_hook_target_count; i++) {
        if (g_execute_hook_targets[i] == mi_addr) {
            goto intercepted;
        }
    }
    
    // Phase 2: interpData 匹配 (捕获不同 MI 对象)
    if (g_execute_hook_interp_count > 0) {
        uintptr_t interp_data = f[10];
        if (interp_data) {
            for (int i = 0; i < g_execute_hook_interp_count; i++) {
                if (g_execute_hook_interp_targets[i] == interp_data) {
                    goto intercepted;
                }
            }
        }
    }
    
    // Phase 3: 方法名匹配 (早期模式 + 兜底)
    // 读取 MI 的 name 字段 (f[2]) 并与已知 DLC 方法名比较
    {
        const char *name = (const char *)f[2];
        if (name && (uintptr_t)name > 0x10000) {
            // 快速前缀检查: DLC 方法名都以 i/I/g 开头
            char c0 = name[0];
            if (c0 == 'i' || c0 == 'I' || c0 == 'g') {
                for (int n = 0; g_early_match_names[n]; n++) {
                    if (strcmp(name, g_early_match_names[n]) == 0) {
                        __atomic_add_fetch(&g_execute_early_intercepts, 1, __ATOMIC_RELAXED);
                        goto intercepted;
                    }
                }
            }
        }
    }
    
    // 不匹配, 调用原始 Execute
    // 周期性统计日志
    if (total == 100 || total == 1000 || total == 5000 || total == 10000 || 
        total == 50000 || total % 100000 == 0) {
        LOGI("[exec-hook] Stats: total=%d, intercepted=%d (early=%d), targets=%d, interp=%d",
             total, 
             __atomic_load_n(&g_execute_intercepted_calls, __ATOMIC_RELAXED),
             __atomic_load_n(&g_execute_early_intercepts, __ATOMIC_RELAXED),
             g_execute_hook_target_count, g_execute_hook_interp_count);
    }
    
    g_orig_execute(methodInfo, args, ret);
    return;

intercepted:
    if (ret) {
        *(int64_t*)ret = 1;  // StackObject.i64 = 1 (bool true)
    }
    {
        int ic = __atomic_add_fetch(&g_execute_intercepted_calls, 1, __ATOMIC_RELAXED);
        if (ic <= 100) {
            const char *name = (const char *)f[2];
            const char *safe_name = (name && (uintptr_t)name > 0x10000) ? name : "?";
            LOGI("[exec-hook] ★ INTERCEPTED Execute(MI=%p, name=%s) -> ret=1 #%d (total=%d, early=%d)",
                 methodInfo, safe_name, ic, total,
                 __atomic_load_n(&g_execute_early_intercepts, __ATOMIC_RELAXED));
        }
    }
}

// 安装 Execute inline hook, 返回 0=成功
static int install_execute_hook(uintptr_t execute_addr) {
    if (!execute_addr) return -1;
    if (g_execute_hook_installed) return 0;
    
    LOGI("[exec-hook] Installing inline hook on Execute @ %p", (void*)execute_addr);
    g_execute_addr = execute_addr;
    
    // 1. 保存原始前 16 字节 (4 条指令)
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        LOGE("[exec-hook] SIGSEGV reading Execute instructions");
        return -1;
    }
    memcpy(g_execute_saved_insns, (void*)execute_addr, 16);
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    LOGI("[exec-hook] Saved instructions: %08x %08x %08x %08x",
         g_execute_saved_insns[0], g_execute_saved_insns[1],
         g_execute_saved_insns[2], g_execute_saved_insns[3]);
    
    // 2. 分配 trampoline (执行保存的 4 条指令, 然后跳回 Execute+16)
    // trampoline 布局:
    //   [0-3]   4 条原始指令 (16 bytes)
    //   [4]     LDR X16, [PC, #8]   (0x58000050)
    //   [5]     BR X16              (0xD61F0200)
    //   [6-7]   .quad Execute+16    (8 bytes)
    // 总共 32 bytes
    
    // 检查保存的指令中是否有 PC 相对指令 (ADRP, ADR, B, BL, LDR literal, etc.)
    // 如果有, trampoline 需要 fixup. 简单做法: 检查并报告.
    int has_pc_relative = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t insn = g_execute_saved_insns[i];
        uint32_t op = insn >> 24;
        // ADRP: 1xx10000 (bit31=1, [28:24]=10000)
        if ((insn & 0x9F000000) == 0x90000000) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is ADRP: 0x%08x", i, insn); }
        // ADR: 0xx10000
        if ((insn & 0x9F000000) == 0x10000000) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is ADR: 0x%08x", i, insn); }
        // B/BL: 000101xx (B) or 100101xx (BL)
        if ((insn >> 26) == 0x05 || (insn >> 26) == 0x25) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is B/BL: 0x%08x", i, insn); }
        // CBZ/CBNZ: 0x34/0x35/0xB4/0xB5
        if (op == 0x34 || op == 0x35 || op == 0xB4 || op == 0xB5) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is CBZ/CBNZ: 0x%08x", i, insn); }
        // TBZ/TBNZ: 0x36/0x37/0xB6/0xB7
        if (op == 0x36 || op == 0x37 || op == 0xB6 || op == 0xB7) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is TBZ/TBNZ: 0x%08x", i, insn); }
        // LDR literal: 0x18/0x1C/0x58/0x5C/0x98/0x9C/0xD8/0xDC
        if (op == 0x18 || op == 0x1C || op == 0x58 || op == 0x5C ||
            op == 0x98 || op == 0x9C || op == 0xD8 || op == 0xDC) { has_pc_relative = 1; LOGW("[exec-hook] insn[%d] is LDR literal: 0x%08x", i, insn); }
    }
    
    if (has_pc_relative) {
        LOGW("[exec-hook] WARNING: PC-relative instructions in saved area, trampoline may crash!");
        LOGW("[exec-hook] Will attempt ADRP fixup...");
    }
    
    // 分配 trampoline RWX 内存
    void *tramp_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp_mem == MAP_FAILED) {
        LOGE("[exec-hook] mmap trampoline failed: %s", strerror(errno));
        return -1;
    }
    
    uint32_t *tramp = (uint32_t *)tramp_mem;
    int ti = 0;
    
    // 写入保存的 4 条指令, 处理 PC 相对指令的 fixup
    for (int i = 0; i < 4; i++) {
        uint32_t insn = g_execute_saved_insns[i];
        
        // ADRP fixup: 重新计算 immhi:immlo 使得在新地址产生相同的结果
        if ((insn & 0x9F000000) == 0x90000000) {
            // ADRP Xd, label
            // Original: PC_old = execute_addr + i*4, target_page = (PC_old & ~0xFFF) + (imm << 12)
            // New:      PC_new = tramp_addr + ti*4, need same target_page
            uintptr_t pc_old = execute_addr + i * 4;
            // 解码原始 imm
            uint32_t immlo = (insn >> 29) & 0x3;
            uint32_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm_orig = (int64_t)(((int64_t)((immhi << 2) | immlo)) << 12);
            // 符号扩展 21+12=33 位
            if (imm_orig & (1LL << 32)) imm_orig |= ~((1LL << 33) - 1);
            
            uintptr_t target_page = (pc_old & ~(uintptr_t)0xFFF) + imm_orig;
            uintptr_t pc_new = (uintptr_t)tramp_mem + ti * 4;
            int64_t new_imm = (int64_t)(target_page - (pc_new & ~(uintptr_t)0xFFF));
            int64_t new_imm_pages = new_imm >> 12;
            
            // 检查是否超出 ±4GB 范围
            if (new_imm_pages > 0xFFFFF || new_imm_pages < -(int64_t)0x100000) {
                LOGE("[exec-hook] ADRP fixup out of range! Cannot hook Execute.");
                munmap(tramp_mem, 4096);
                return -1;
            }
            
            uint32_t rd = insn & 0x1F;
            uint32_t new_immlo = ((uint32_t)new_imm_pages) & 0x3;
            uint32_t new_immhi = (((uint32_t)new_imm_pages) >> 2) & 0x7FFFF;
            insn = 0x90000000 | (new_immlo << 29) | (new_immhi << 5) | rd;
            LOGI("[exec-hook] ADRP fixup: insn[%d] -> 0x%08x (target_page=%p)", i, insn, (void*)target_page);
        }
        
        tramp[ti++] = insn;
    }
    
    // 跳回 Execute+16
    tramp[ti++] = 0x58000050;  // LDR X16, [PC, #8]
    tramp[ti++] = 0xD61F0200;  // BR X16
    uint64_t *ret_addr = (uint64_t *)&tramp[ti];
    *ret_addr = (uint64_t)(execute_addr + 16);
    
    __builtin___clear_cache((char*)tramp_mem, (char*)tramp_mem + 4096);
    
    g_execute_trampoline = tramp_mem;
    g_orig_execute = (execute_func_t)tramp_mem;
    
    LOGI("[exec-hook] Trampoline @ %p (returns to %p)", tramp_mem, (void*)(execute_addr + 16));
    
    // 3. 安装 hook: 覆盖 Execute 入口 16 字节
    uintptr_t page = execute_addr & ~(uintptr_t)0xFFF;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("[exec-hook] mprotect RWX failed for Execute: %s", strerror(errno));
        if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
            LOGE("[exec-hook] mprotect RW also failed");
            return -1;
        }
    }
    // 跨页检查
    uintptr_t page_end = (execute_addr + 16) & ~(uintptr_t)0xFFF;
    if (page_end != page) {
        mprotect((void *)page_end, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    }
    
    uint32_t *target_code = (uint32_t *)execute_addr;
    target_code[0] = 0x58000050;  // LDR X16, [PC, #8]
    target_code[1] = 0xD61F0200;  // BR X16
    uint64_t *hook_addr = (uint64_t *)&target_code[2];
    *hook_addr = (uint64_t)(void*)hook_execute_func;
    
    __builtin___clear_cache((char *)execute_addr, (char *)(execute_addr + 16));
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    if (page_end != page) {
        mprotect((void *)page_end, 0x1000, PROT_READ | PROT_EXEC);
    }
    
    g_execute_hook_installed = 1;
    LOGI("[exec-hook] ★ Execute hook installed! Hook=%p, Trampoline=%p, Execute=%p",
         (void*)hook_execute_func, tramp_mem, (void*)execute_addr);
    
    // v6.34: 保存 Execute 偏移到缓存, 下次启动可立即安装 hook
    if (g_il2cpp_base_for_cache) {
        uint64_t offset = execute_addr - g_il2cpp_base_for_cache;
        const char *cache_path = "/data/user/0/com.ztgame.yyzy/cache/exec_v34";
        FILE *cf = fopen(cache_path, "wb");
        if (cf) {
            fwrite(&g_il2cpp_base_for_cache, 8, 1, cf);
            fwrite(&offset, 8, 1, cf);
            fclose(cf);
            LOGI("[exec-hook] v6.34: ★ Cached Execute offset 0x%lx (base=%p)", 
                 (unsigned long)offset, (void*)g_il2cpp_base_for_cache);
        }
    }
    
    return 0;
}

// ===== v6.34: 从缓存的偏移量尽早安装 Execute hook =====
// 首次运行时缓存 Execute 偏移; 后续重启 <1 秒内安装 hook
// 这解决了 "游戏在 hook 安装前就缓存了 DLC 状态" 的根本问题
static int try_early_execute_hook(void) {
    if (g_execute_hook_installed) return 0;
    
    // 1. 轮询等待 libil2cpp.so 加载 (最多 3 秒, 每 100ms 检查一次)
    // Unity 在主线程加载 libil2cpp.so, 我们的线程可能先启动
    uintptr_t il2cpp_base = 0;
    for (int attempt = 0; attempt < 30 && !il2cpp_base; attempt++) {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp) { usleep(100000); continue; }
        
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libil2cpp.so") && strstr(line, "r-xp")) {
                unsigned long addr;
                if (sscanf(line, "%lx", &addr) == 1) {
                    il2cpp_base = (uintptr_t)addr;
                }
                break;
            }
        }
        fclose(fp);
        
        if (!il2cpp_base) {
            if (attempt == 0) LOGI("[exec-hook] v6.34: Waiting for libil2cpp.so...");
            usleep(100000); // 100ms
        }
    }
    
    if (!il2cpp_base) {
        LOGI("[exec-hook] v6.34: libil2cpp.so not loaded yet, skip early hook");
        return -1;
    }
    LOGI("[exec-hook] v6.34: libil2cpp.so base = %p", (void*)il2cpp_base);
    g_il2cpp_base_for_cache = il2cpp_base;
    
    // 2. 读取缓存文件
    const char *cache_path = "/data/user/0/com.ztgame.yyzy/cache/exec_v34";
    FILE *cf = fopen(cache_path, "rb");
    if (!cf) {
        LOGI("[exec-hook] v6.34: No cached Execute offset (first run), will cache after discovery");
        return -1;
    }
    
    uint64_t cached_base, cached_offset;
    int ok = (fread(&cached_base, 8, 1, cf) == 1 && fread(&cached_offset, 8, 1, cf) == 1);
    fclose(cf);
    
    if (!ok || cached_offset == 0 || cached_offset > 0x10000000) {
        LOGI("[exec-hook] v6.34: Invalid cache data, skip");
        return -1;
    }
    
    // 3. 计算 Execute 运行时地址
    uintptr_t exec_addr = il2cpp_base + cached_offset;
    
    // 4. 验证: 读取目标地址的指令, 确认看起来像一个函数入口
    install_sigsegv_handler();
    g_in_safe_access = 1;
    int valid = 0;
    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        uint32_t first_insn = *(volatile uint32_t *)exec_addr;
        // Execute 入口应该是 STP (0xA9xx) 指令
        if ((first_insn >> 24) == 0xA9) {
            valid = 1;
        }
        LOGI("[exec-hook] v6.34: Cached Execute @ %p, first insn=0x%08x, valid=%d",
             (void*)exec_addr, first_insn, valid);
    }
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    if (!valid) {
        LOGW("[exec-hook] v6.34: Cached offset invalid (lib may have changed), skip");
        unlink(cache_path);
        return -1;
    }
    
    // 5. 安装 Execute hook — 此时无 MI 目标, 但名称匹配会生效!
    LOGI("[exec-hook] v6.34: ★ Installing EARLY Execute hook from cache (offset=0x%lx)",
         (unsigned long)cached_offset);
    int ret = install_execute_hook(exec_addr);
    if (ret == 0) {
        LOGI("[exec-hook] v6.34: ★★★ EARLY Execute hook ACTIVE! Name-based DLC interception enabled");
    }
    return ret;
}

// 分配 RWX 内存并写入 ARM64 代码
static void* alloc_executable_stub(const uint32_t *code, size_t code_size) {
    // 使用 mmap 分配可执行内存
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("[stub] mmap RWX failed: %s", strerror(errno));
        return NULL;
    }
    memcpy(mem, code, code_size);
    __builtin___clear_cache((char*)mem, (char*)mem + code_size);
    LOGI("[stub] Allocated executable stub @ %p (%zu bytes)", mem, code_size);
    return mem;
}

// 初始化 ARM64 stubs
static void init_dlc_stubs(void) {
    if (g_stub_return_true) return; // 已初始化
    
    // Stub 1: methodPointer stub
    // HybridCLR 调用约定: ret_type method(void* this, arg1, ..., MethodInfo* mi)
    // 对于 bool isUnlockRole(int roleId):
    //   X0=this, W1=roleId, X2=MethodInfo*
    // 直接返回 1 (true)
    static const uint32_t stub_ret_true[] = {
        0x52800020,  // MOV W0, #1
        0xD65F03C0,  // RET
    };
    g_stub_return_true = alloc_executable_stub(stub_ret_true, sizeof(stub_ret_true));
    
    // Stub 2: invoker stub
    // il2cpp_runtime_invoke 调用的是 invoker_method:
    //   void* invoker(Il2CppMethodPointer methodPtr, const MethodInfo* method,
    //                 void* obj, void** args, void** exception)
    // 对于 bool 返回值, invoker 需要:
    //   1. 调用 methodPtr 获取结果
    //   2. 将结果 box 成 Il2CppObject*
    // 简单做法: 直接返回一个 boxed bool (跳过，直接让 methodPointer 返回)
    // 但实际上 invoker 的返回值是 Il2CppObject*，不是 bool
    // 所以我们不替换 invoker, 只替换 methodPointer
    // invoker 会调用新的 methodPointer 获得 W0=1，然后正常 box 返回
    
    if (g_stub_return_true) {
        LOGI("[stub] ARM64 stubs initialized: ret_true=%p", g_stub_return_true);
    } else {
        LOGE("[stub] Failed to initialize ARM64 stubs");
    }
}

// 扫描内存查找 ProtoLogin 实例（与 RoleInfo 扫描相同原理）
static int find_proto_login_instance(void) {
    if (!g_proto_login_cls) {
        g_proto_login_cls = fn_class_from_name(g_csharp_image, "", "ProtoLogin");
        if (!g_proto_login_cls) {
            LOGE("[dlc] ProtoLogin class not found!");
            return 0;
        }
        LOGI("[dlc] ProtoLogin klass: %p", g_proto_login_cls);
    }

    uintptr_t klass_val = (uintptr_t)g_proto_login_cls;
    g_proto_login_inst = 0;
    int candidates = 0;

    parse_maps();
    install_sigsegv_handler();

    // 辅助宏：指针有效性检查
    // BAD_PTR: 非NULL且太小（不可能是堆地址）
    // UNALIGNED_PTR: 非NULL且未8字节对齐（C#对象指针必须对齐）
    #define BAD_PTR(v) ((v) != 0 && (v) < 0x10000)
    #define UNALIGNED_PTR(v) ((v) != 0 && ((v) & 0x7) != 0)

    for (int r = 0; r < g_region_count && !g_proto_login_inst; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        size_t size = region->end - region->start;
        if (size < 0x90 || size > MAX_SCAN_SIZE) continue;
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;

        uint8_t *base = (uint8_t *)region->start;
        for (size_t off = 0; off <= size - 0x90; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; break; }

            uintptr_t *p = (uintptr_t *)(base + off);
            if (*p != klass_val) { g_in_safe_access = 0; continue; }

            uintptr_t obj = (uintptr_t)(base + off);

            // 验证 monitor (+8): 真实 ProtoLogin 的 monitor 通常为 0
            uintptr_t monitor = *(volatile uintptr_t *)(obj + 8);
            if (monitor != 0 && monitor < 0x10000) { g_in_safe_access = 0; continue; }

            // 验证 0x10-0x28 区域: ProtoLogin 的实例字段从 0x30 开始
            // 0x10-0x28 应该全为 0 或只有很小的值（如 hash code）
            // 真实实例: [+0x10]=0, [+0x20]=0, [+0x28]=0
            // 假阳性: [+0x10]=0x722bf0b988 (非零堆指针 → 明显是假的)
            uintptr_t v10 = *(volatile uintptr_t *)(obj + 0x10);
            uintptr_t v20 = *(volatile uintptr_t *)(obj + 0x20);
            uintptr_t v28 = *(volatile uintptr_t *)(obj + 0x28);
            if (v10 > 0x100000 || v20 > 0x100000 || v28 > 0x100000) {
                g_in_safe_access = 0;
                continue; // 字段0x10-0x28有大值 → 不是ProtoLogin
            }

            // 读取关键字段
            uintptr_t mLoginData  = *(volatile uintptr_t *)(obj + 0x30);
            uintptr_t mRestore    = *(volatile uintptr_t *)(obj + 0x38);
            uintptr_t mDLCSet     = *(volatile uintptr_t *)(obj + 0x40);
            uintptr_t mDLCSetInfo = *(volatile uintptr_t *)(obj + 0x48);
            uintptr_t mProd2DLC   = *(volatile uintptr_t *)(obj + 0x50);
            uintptr_t baseRoles   = *(volatile uintptr_t *)(obj + 0x58);
            uintptr_t packAll     = *(volatile uintptr_t *)(obj + 0x60);
            g_in_safe_access = 0;

            // 检查1: 指针值合法性（非NULL时必须是有效堆地址）
            if (BAD_PTR(mLoginData) || BAD_PTR(mRestore) || BAD_PTR(mDLCSet) ||
                BAD_PTR(mDLCSetInfo) || BAD_PTR(mProd2DLC) || BAD_PTR(baseRoles)) {
                continue;
            }

            // 检查2: 指针对齐性（C#对象引用必须8字节对齐）
            // 假阳性特征: mRestore=0x...26b, mDLCSetInfo=0x...11e 等非对齐地址
            if (UNALIGNED_PTR(mRestore) || UNALIGNED_PTR(mDLCSetInfo) || 
                UNALIGNED_PTR(mProd2DLC)) {
                continue; // 有未对齐指针 → 假阳性
            }

            // 检查3: mDLCSet != BaseRoles（假阳性中常出现两者相同）
            if (mDLCSet != 0 && baseRoles != 0 && mDLCSet == baseRoles) {
                candidates++;
                LOGW("[dlc] Candidate #%d @ 0x%" PRIxPTR
                     " rejected: mDLCSet==BaseRoles==%p (false positive)",
                     candidates, obj, (void*)mDLCSet);
                continue;
            }

            // 检查4: mLoginData 不应指向对象自身附近（假阳性特征）
            if (mLoginData != 0) {
                int64_t delta = (int64_t)mLoginData - (int64_t)obj;
                if (delta >= 0 && delta < 0x200) {
                    candidates++;
                    LOGW("[dlc] Candidate #%d @ 0x%" PRIxPTR
                         " rejected: mLoginData self-referencing (delta=0x%" PRIx64 ")",
                         candidates, obj, (uint64_t)delta);
                    continue;
                }
            }

            // 至少需要 mLoginData 或 baseRoles 非空（ProtoLogin 初始化标志）
            int non_null = 0;
            if (mLoginData)  non_null++;
            if (mRestore)    non_null++;
            if (mDLCSet)     non_null++;
            if (mDLCSetInfo) non_null++;
            if (mProd2DLC)   non_null++;
            if (baseRoles)   non_null++;

            candidates++;
            LOGI("[dlc] ProtoLogin candidate #%d @ 0x%" PRIxPTR
                 ": mDLCSet=%p, BaseRoles=%p, mLoginData=%p, packAll=%p, non_null=%d",
                 candidates, obj, (void*)mDLCSet, (void*)baseRoles,
                 (void*)mLoginData, (void*)packAll, non_null);

            // 需要至少 mLoginData 或 (baseRoles+packAll) 有值
            if (non_null < 1 || (!mLoginData && !baseRoles)) {
                LOGW("[dlc]   Rejected: insufficient initialization (non_null=%d)", non_null);
                continue;
            }

            g_proto_login_inst = obj;
            break;
        }
    }
    #undef BAD_PTR
    #undef UNALIGNED_PTR
    uninstall_sigsegv_handler();

    if (g_proto_login_inst) {
        LOGI("[dlc] Found ProtoLogin @ 0x%" PRIxPTR, g_proto_login_inst);
    } else {
        LOGW("[dlc] No ProtoLogin instance found (%d candidates)", candidates);
    }
    return g_proto_login_inst != 0;
}

// DLC 解锁: 是否已输出过详细日志（避免每次调用都输出几百行）
static volatile int g_dlc_verbose_logged = 0;
// DLC 后台持续解锁标记
static volatile int g_dlc_unlocked = 0;
// MethodInfo hook 是否已安装
static volatile int g_mi_hooks_installed = 0;
// 保存的原始 methodPointer / invoker 值
static uintptr_t g_orig_isUnlockRole_ptr = 0;
static uintptr_t g_orig_isUnlockRole_invoker = 0;

// 主 DLC 解锁函数 (v4: MethodInfo 改写 + 诊断)
// 核心策略: 
// 1. 找到 isUnlockRole 的 MethodInfo
// 2. Dump MethodInfo 内存来理解 HybridCLR 的判定标志
// 3. 分配 ARM64 stub (返回 true)
// 4. 修改 MethodInfo 让解释器走 native 路径
// 5. 同时对比 AOT 方法的 MethodInfo 来找差异
static int do_unlock_all_dlc(void) {
    if (init_il2cpp_context() != 0) return -1;

    if (!fn_runtime_invoke) {
        LOGE("[dlc] il2cpp_runtime_invoke not resolved!");
        return -1;
    }

    if (fn_thread_attach && g_domain) {
        fn_thread_attach(g_domain);
    }

    if (!g_proto_login_cls) {
        g_proto_login_cls = fn_class_from_name(g_csharp_image, "", "ProtoLogin");
    }
    if (!g_proto_login_cls) {
        LOGE("[dlc] ProtoLogin class not found!");
        return -1;
    }

    int verbose = !g_dlc_verbose_logged;
    if (verbose) g_dlc_verbose_logged = 1;

    // ===== 1) 找 ProtoLogin 实例 =====
    if (!find_proto_login_instance()) {
        LOGW("[dlc] ProtoLogin not found - please enter main menu first");
        return -2;
    }

    // ===== 2) 获取关键方法 =====
    Il2CppMethodInfo m_isUnlock = fn_class_get_method_from_name(g_proto_login_cls, "isUnlockRole", 1);
    Il2CppMethodInfo m_addDLC   = fn_class_get_method_from_name(g_proto_login_cls, "AddDLC", 1);
    if (!m_isUnlock) {
        LOGE("[dlc] isUnlockRole not found!");
        return -1;
    }
    LOGI("[dlc] isUnlockRole MI=%p, AddDLC MI=%p", m_isUnlock, m_addDLC);

    void *exc = NULL;
    volatile int sigsegv_hit = 0;

    #define SAFE_INVOKE(result_var, method, obj, params, exc_ptr) do { \
        sigsegv_hit = 0; \
        install_sigsegv_handler(); \
        g_in_safe_access = 1; \
        if (sigsetjmp(g_jmpbuf, 1) != 0) { \
            g_in_safe_access = 0; \
            uninstall_sigsegv_handler(); \
            sigsegv_hit = 1; \
            result_var = NULL; \
        } else { \
            result_var = fn_runtime_invoke(method, obj, params, (void **)exc_ptr); \
            g_in_safe_access = 0; \
            uninstall_sigsegv_handler(); \
        } \
    } while(0)

    #define SAFE_UNBOX_INT(result, boxed, default_val) do { \
        result = default_val; \
        if (boxed && !sigsegv_hit) { \
            install_sigsegv_handler(); \
            g_in_safe_access = 1; \
            if (sigsetjmp(g_jmpbuf, 1) == 0) { \
                result = *(int32_t *)((uint8_t *)(boxed) + 0x10); \
            } \
            g_in_safe_access = 0; \
            uninstall_sigsegv_handler(); \
        } \
    } while(0)

    // ===== 3) 验证实例 =====
    {
        int32_t test_rid = 0;
        void *params[1] = { &test_rid };
        exc = NULL;
        void *result = NULL;
        SAFE_INVOKE(result, m_isUnlock, (void *)g_proto_login_inst, params, &exc);
        if (sigsegv_hit) {
            LOGW("[dlc] SIGSEGV calling isUnlockRole(0) - instance INVALID, discarding");
            g_proto_login_inst = 0;
            return -3;
        }
        int val = -1;
        SAFE_UNBOX_INT(val, result, -1);
        LOGI("[dlc] Instance validation: isUnlockRole(0) = %d", val);
    }

    // ===== 4) Dump MethodInfo 内存 (诊断 HybridCLR 结构) =====
    // MethodInfo 结构 (il2cpp + HybridCLR):
    // [0]  +0x00: methodPointer (函数指针)
    // [1]  +0x08: invoker_method (il2cpp_runtime_invoke 使用)
    // [2]  +0x10: name (const char*)
    // [3]  +0x18: klass (Il2CppClass*)
    // [4]  +0x20: return_type (Il2CppType*)
    // [5]  +0x28: parameters (ParameterInfo*)
    // [6]  +0x30: 通常是 genericContainerHandle 或其他
    // [7]  +0x38: token
    // [8]  +0x40: flags / iflags 等
    // [9]  +0x48: slot
    // [10] +0x50: parameters_count
    // [11] +0x58: 标志位 (is_generic, is_inflated, wrapper_type, is_marshaled_from_native, ...)
    //            HybridCLR 可能在这里标记 isInterpreterMethod
    // +0x60...: HybridCLR 扩展字段
    if (verbose) {
        LOGI("[dlc] ===== MethodInfo dump: isUnlockRole =====");
        uintptr_t *mi = (uintptr_t *)m_isUnlock;
        install_sigsegv_handler();
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) == 0) {
            for (int i = 0; i < 24; i++) {
                uintptr_t val = mi[i];
                // 尝试判断是否是字符串
                const char *str_hint = "";
                if (i == 2 && val > 0x10000) {
                    // name 字段
                    str_hint = (const char*)val;
                }
                LOGI("[dlc-mi] isUnlockRole [%2d] +0x%02x = 0x%016" PRIxPTR " (%ld) %s",
                     i, i*8, val, (long)val, 
                     (i == 2 && val > 0x10000) ? str_hint : "");
            }
        }
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();

        // 同时 dump 一个 AOT 方法的 MethodInfo 做对比
        // 用 AddDLC 或一个不太可能是 HybridCLR 的方法
        // 尝试从 System.Object 找一个 AOT 方法
        Il2CppClass obj_cls = fn_class_from_name(g_csharp_image, "System", "Object");
        if (!obj_cls) {
            // 从 mscorlib 查找
            // 遍历 assemblies 找 mscorlib
            size_t asm_count = 0;
            Il2CppAssembly *asms = fn_domain_get_assemblies(g_domain, &asm_count);
            for (size_t a = 0; a < asm_count && !obj_cls; a++) {
                Il2CppImage img = fn_assembly_get_image(asms[a]);
                if (!img) continue;
                const char *iname = fn_image_get_name(img);
                if (iname && (strstr(iname, "mscorlib") || strstr(iname, "corlib"))) {
                    obj_cls = fn_class_from_name(img, "System", "Object");
                    LOGI("[dlc] Found System.Object in %s", iname);
                }
            }
        }
        if (obj_cls) {
            Il2CppMethodInfo m_tostr = fn_class_get_method_from_name(obj_cls, "ToString", 0);
            if (m_tostr) {
                LOGI("[dlc] ===== MethodInfo dump: Object.ToString (AOT reference) =====");
                uintptr_t *mi2 = (uintptr_t *)m_tostr;
                install_sigsegv_handler();
                g_in_safe_access = 1;
                if (sigsetjmp(g_jmpbuf, 1) == 0) {
                    for (int i = 0; i < 24; i++) {
                        uintptr_t val = mi2[i];
                        const char *str_hint = "";
                        if (i == 2 && val > 0x10000) str_hint = (const char*)val;
                        LOGI("[dlc-mi] Object.ToString  [%2d] +0x%02x = 0x%016" PRIxPTR " (%ld) %s",
                             i, i*8, val, (long)val,
                             (i == 2 && val > 0x10000) ? str_hint : "");
                    }
                }
                g_in_safe_access = 0;
                uninstall_sigsegv_handler();
            }
        }

        // 也 dump AddDLC 的 MethodInfo (也是 HybridCLR 方法)
        if (m_addDLC) {
            LOGI("[dlc] ===== MethodInfo dump: AddDLC =====");
            uintptr_t *mi3 = (uintptr_t *)m_addDLC;
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                for (int i = 0; i < 24; i++) {
                    uintptr_t val = mi3[i];
                    const char *str_hint = "";
                    if (i == 2 && val > 0x10000) str_hint = (const char*)val;
                    LOGI("[dlc-mi] AddDLC          [%2d] +0x%02x = 0x%016" PRIxPTR " (%ld) %s",
                         i, i*8, val, (long)val,
                         (i == 2 && val > 0x10000) ? str_hint : "");
                }
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
        }

        // dump IsUnlockAllDLC 的 MethodInfo
        Il2CppMethodInfo m_isUnlockAll = fn_class_get_method_from_name(g_proto_login_cls, "IsUnlockAllDLC", 1);
        if (m_isUnlockAll) {
            LOGI("[dlc] ===== MethodInfo dump: IsUnlockAllDLC =====");
            uintptr_t *mi4 = (uintptr_t *)m_isUnlockAll;
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                for (int i = 0; i < 24; i++) {
                    uintptr_t val = mi4[i];
                    const char *str_hint = "";
                    if (i == 2 && val > 0x10000) str_hint = (const char*)val;
                    LOGI("[dlc-mi] IsUnlockAllDLC  [%2d] +0x%02x = 0x%016" PRIxPTR " (%ld) %s",
                         i, i*8, val, (long)val,
                         (i == 2 && val > 0x10000) ? str_hint : "");
                }
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
        }
    }

    // ===== 5) 查找 System.Boolean 类（用于自定义 invoker boxing）=====
    if (!g_boolean_class) {
        // 从 mscorlib 查找 System.Boolean
        size_t asm_count = 0;
        Il2CppAssembly *asms = fn_domain_get_assemblies(g_domain, &asm_count);
        for (size_t a = 0; a < asm_count && !g_boolean_class; a++) {
            Il2CppImage img = fn_assembly_get_image(asms[a]);
            if (!img) continue;
            const char *iname = fn_image_get_name(img);
            if (iname && (strstr(iname, "mscorlib") || strstr(iname, "corlib"))) {
                g_boolean_class = fn_class_from_name(img, "System", "Boolean");
                if (g_boolean_class)
                    LOGI("[dlc] System.Boolean class: %p (from %s)", g_boolean_class, iname);
            }
        }
        if (!g_boolean_class) {
            LOGE("[dlc] System.Boolean class not found!");
        }
    }

    // ===== 6) 完整 MethodInfo patch — 伪装 HybridCLR 方法为 AOT =====
    // 策略 v6: 同时替换 methodPointer 和 invoker，并清除 interpData + HybridCLR 标志
    // 这样解释器内部调用也会走我们的 C 函数，而不是解释 IL 字节码
    if (!g_mi_hooks_installed && g_boolean_class && fn_object_new) {
        init_dlc_stubs();
        
        // ===== v6.32: 在 patch 任何 MI 之前, 先找到 Execute 并安装 hook =====
        // 从第一个 HybridCLR 方法的原始 f[0] (bridge addr) 反汇编找到 Execute
        if (!g_execute_hook_installed) {
            // 用 isUnlockRole 的原始 f[0] 作为 bridge (patch 前)
            uintptr_t bridge_for_exec = 0;
            Il2CppMethodInfo tmp_mi = fn_class_get_method_from_name(g_proto_login_cls, "isUnlockRole", 1);
            if (tmp_mi) {
                uintptr_t *tf = (uintptr_t *)tmp_mi;
                LOGI("[dlc] v6.32: isUnlockRole tmp_mi=%p f[0]=%p custom_ret_true=%p",
                     tmp_mi, (void*)tf[0], (void*)(uintptr_t)custom_return_true_method);
                // f[0] 是代码指针 (libil2cpp.so 范围), 值如 0x7209a46cb4
                // 注意: 地址只有 39 位, 不要用 0x700000000000ULL 比较
                if (tf[0] != (uintptr_t)custom_return_true_method && tf[0] > 0x10000) {
                    bridge_for_exec = tf[0];
                }
            }
            // 备选: 用已保存的原始 methodPointer
            if (!bridge_for_exec && g_orig_isUnlockRole_ptr) {
                bridge_for_exec = g_orig_isUnlockRole_ptr;
            }
            // 备选: 从 AddDLC 的 f[0] 获取
            if (!bridge_for_exec && m_addDLC) {
                uintptr_t *af = (uintptr_t *)m_addDLC;
                if (af[0] > 0x10000 && af[0] != (uintptr_t)custom_return_true_method) {
                    bridge_for_exec = af[0];
                }
            }
            
            if (bridge_for_exec) {
                LOGI("[dlc] v6.32: Bridge address for Execute discovery: %p", (void*)bridge_for_exec);
                uintptr_t exec_addr = find_execute_from_bridge(bridge_for_exec);
                if (exec_addr) {
                    int hook_ret = install_execute_hook(exec_addr);
                    LOGI("[dlc] v6.32: install_execute_hook returned %d", hook_ret);
                } else {
                    LOGE("[dlc] v6.32: Could not find Execute from bridge!");
                }
            } else {
                LOGE("[dlc] v6.32: Could not get bridge address for Execute discovery!");
            }
        }
        
        // v6.3: 用方法迭代 patch ProtoLogin 所有匹配方法（解决同名方法多个重载只 patch 第一个的问题）
        // 只 patch 返回 bool 的方法名
        // v6.27: 恢复 v6.10 完整方法列表
        // v6.16 删减了 IsDLCRole/IsUnlockByFirstGame/IsUnlockGuBao，导致 DLC 无法解锁
        // 当时的"按钮失灵"实际是浮窗拦截触摸导致的（v6.18 已用 FLAG_NOT_TOUCH_MODAL 修复）
        const char *safe_method_names[] = {
            "isUnlockRole", "IsDLCRole", "IsUnlockAllDLC",
            "IsUnlockByFirstGame", "IsUnlockGuBao",
        };
        int num_safe = sizeof(safe_method_names) / sizeof(safe_method_names[0]);
        int patched = 0;
        
        // 迭代 ProtoLogin 类的所有方法
        void *iter = NULL;
        Il2CppMethodInfo mi;
        while ((mi = fn_class_get_methods(g_proto_login_cls, &iter)) != NULL) {
            const char *mname = fn_method_get_name(mi);
            if (!mname) continue;
            
            // 检查是否在安全方法列表中
            int found = 0;
            for (int s = 0; s < num_safe; s++) {
                if (strcmp(mname, safe_method_names[s]) == 0) { found = 1; break; }
            }
            if (!found) continue;
            
            uintptr_t *f = (uintptr_t *)mi;
            
            // 跳过已经 patch 过的方法
            if (f[0] == (uintptr_t)custom_return_true_method) {
                LOGI("[dlc] %s already patched, skip (MI=%p)", mname, mi);
                continue;
            }
            
            LOGI("[dlc] BEFORE %s: mPtr=%p inv=%p name=%p interpData=%p MI=%p",
                 mname, (void*)f[0], (void*)f[1], (void*)f[2], (void*)f[10], mi);
            
            // v6.32: 注册到 Execute hook 目标列表 (在 patch f[0] 之前!)
            execute_hook_add_target(mi);
            
            // 设置页面可写
            uintptr_t page = (uintptr_t)mi & ~(uintptr_t)0xFFF;
            mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE);
            uintptr_t page_end = ((uintptr_t)mi + 0x68) & ~(uintptr_t)0xFFF;  // MI=104 bytes=0x68 (Unity 2020)
            if (page_end != page)
                mprotect((void *)page_end, 0x1000, PROT_READ | PROT_WRITE);
            
            // 保存 isUnlockRole 的原始 methodPointer + invoker（第一次遇到）
            if (strcmp(mname, "isUnlockRole") == 0 && g_orig_isUnlockRole_ptr == 0) {
                g_orig_isUnlockRole_ptr = f[0];
                g_orig_isUnlockRole_invoker = f[1];
                LOGI("[dlc] v6.29: Saved original isUnlockRole: mPtr=%p invoker=%p interpData=%p",
                     (void*)f[0], (void*)f[1], (void*)f[10]);
            }
            
            // ===== v6.14: Unity 2020 MethodInfo 字段偏移 (无 virtualMethodPointer!) =====
            // Unity 2020.3.49f1c1 MethodInfo layout (ARM64, 104 bytes = 0x68, 13 qwords):
            //   f[0]  = 0x00: methodPointer
            //   f[1]  = 0x08: invoker_method          ← Unity 2020 没有 virtualMethodPointer!
            //   f[2]  = 0x10: name
            //   f[3]  = 0x18: klass
            //   f[4]  = 0x20: return_type
            //   f[5]  = 0x28: parameters
            //   f[6]  = 0x30: rgctx_data/methodMetadataHandle
            //   f[7]  = 0x38: genericMethod/genericContainerHandle
            //   f[8]  = 0x40: token(4) + flags(2) + iflags(2)
            //   f[9]  = 0x48: slot(2) + params_count(1) + bitfield(1) + padding(4)
            //                 bitfield byte at 0x4B:
            //                   bit0: is_generic, bit1: is_inflated, bit2: wrapper_type,
            //                   bit3: is_marshaled_from_native,
            //                   bit4: initInterpCallMethodPointer, bit5: isInterpterImpl
            //   f[10] = 0x50: interpData (InterpMethodInfo*)   [HybridCLR]
            //   f[11] = 0x58: methodPointerCallByInterp        [HybridCLR]
            //   f[12] = 0x60: virtualMethodPointerCallByInterp [HybridCLR]
            
            // f[0] methodPointer → 我们的 C 函数（直接调用路径）
            f[0] = (uintptr_t)custom_return_true_method;
            // f[1] invoker_method → 自定义 invoker (il2cpp_runtime_invoke 走这里)
            f[1] = (uintptr_t)custom_bool_true_invoker;
            // f[2] = name → 不动!
            // v6.29: 不再清除 interpData! 保留原始 InterpMethodInfo,
            // 让解释器的 CallInterp_void 路径能执行原始 IL 代码。
            // 原始 IL 代码会读取 DLCSet 数据来判断 DLC 是否解锁。
            // 之前设 f[10]=0 是错误的: 已变换的调用者使用 CallInterp_void
            // 直接读 interpData, 设为 NULL 不会触发 re-Transform,
            // 只会让解释器读到 NULL 然后 SIGSEGV 或者根本不被调用。
            // 保留 interpData 让真实 IL 逻辑在正确的 DLCSet 数据上运行。
            // --- f[10] 保持原样 ---
            
            // v6.31: 全新策略 — 修改 resolveDatas 中引用的方法
            // 发现: codes(在 interpData+0x08)所有方法相同 = 它们都执行同一模板
            // 行为差异来自 resolveDatas(在 interpData+0x18)
            // IR 指令使用 resolveDatas 中的 MethodInfo* 来调用子方法
            // 策略: 保留 interpData 不变, 修改 resolveDatas 中的每个 MethodInfo 的 f[11]
            //   这样当 IR 指令执行 CallCommonNativeInstance 时
            //   会调用我们的 bridge 返回 true
            //
            // 但更简单的方法: 直接修改 codes 内容!
            // IR codes (8 bytes): 0x0004 0x0001 | 0x0001 0x0004
            //   如果指令1 (opcode=4) 是某种调用指令
            //   指令2 (opcode=1) 是 RetVar_ret_1 返回
            //   我们可以把指令1 替换为 LdcVarConst_1 (opcode=?)
            //
            // 策略: 分配新的 codes 内存, 只包含 RetVar_ret_1
            //   但返回值槽未初始化... 不安全.
            //
            // 最终策略: 分配新 codes, 复制原始 codes,
            //   修改 resolveDatas 里引用的 MI 的 f[0]/f[11]
            if (f[10]) {
                uint8_t *imi_raw = (uint8_t*)f[10];
                uintptr_t resolve_ptr = *(uintptr_t*)(imi_raw + 0x18);
                
                LOGI("[dlc] v6.31 %s: interpData=%p resolveDatas=%p", mname, (void*)f[10], (void*)resolve_ptr);
                
                if (resolve_ptr && resolve_ptr > 0x1000) {
                    // dump resolveDatas 前 64 字节 (8 qwords) — 仅诊断
                    // v6.33: resolveDatas 包含 packed IR 操作码参数，不是指针!
                    // 之前把 packed 值误当指针解引用导致 SIGSEGV 崩溃。
                    // Execute hook (v6.32) 才是正确的拦截方式。
                    uintptr_t *rd = (uintptr_t *)resolve_ptr;
                    LOGI("[dlc] v6.33 %s resolveDatas (diagnostic only):", mname);
                    for (int ri = 0; ri < 8; ri++) {
                        uintptr_t rval = rd[ri];
                        LOGI("[dlc]   rd[%d] = 0x%016lx", ri, (unsigned long)rval);
                    }
                }
                
                // ★ 不设 interpData=NULL, 保留原始 interpData
                // 不清除 bit5, 保留 isInterpterImpl=true
                // 这样解释器仍然执行原始 IR codes
                // 但 IR codes 中引用的子方法已被 patch
            } else {
                LOGI("[dlc] v6.31 %s: no interpData", mname);
            }
            
            // v6.29: f[11]/f[12] 指向桥接函数 (供 CallNativeStatic 路径使用)
            f[11] = (uintptr_t)custom_hybridclr_bridge_bool_true;
            f[12] = (uintptr_t)custom_hybridclr_bridge_bool_true;
            // v6.31: 保留 bit5 (isInterpterImpl=true)! 不清除!
            // 让解释器继续执行原始 IR codes
            // 但 IR codes 中调用的子方法已被我们 patch
            // 只设 bit4 (initInterpCallMethodPointer)
            uint8_t *bitfield = (uint8_t *)mi + 0x4B;
            *bitfield = *bitfield | (1 << 4);  // 不清 bit5!
            
            LOGI("[dlc] ★ %s PATCHED: mPtr=%p inv=%p bridge=%p bf=0x%02x interpData=%p MI=%p (v6.29)",
                 mname, (void*)f[0], (void*)f[1], (void*)f[11], *((uint8_t *)mi + 0x4B), (void*)f[10], mi);
            
            if (strcmp(mname, "isUnlockRole") == 0) {
                LOGI("[dlc] MI-DUMP %s: f[0]=%p f[1]=%p f[10]=%p f[11]=%p f[12]=%p MI=%p",
                     mname, (void*)f[0], (void*)f[1], (void*)f[10], (void*)f[11], (void*)f[12], mi);
            }
            
            patched++;
        }

        // ===== 6a-extra) 补充 fn_class_get_method_from_name 查找迭代遗漏的方法 =====
        // v6.8 FIX: 之前只尝试 param_count=0,1，导致 2 参数方法(isUnlockByItem, 
        // IsUnlockByGameId, IsUnlockByGameIds) 未被找到！现在尝试 0-3 参数。
        // 新增 isUnlockByItem — 这是 UI 直接调用的关键方法！
        // v6.27: 恢复 v6.10 完整列表（isUnlockByItem 是 UI 直接调用的关键方法）
        const char *extra_proto_methods[] = {"IsDianCang", "IsOldPlayer", "isUnlockDLC", 
                                              "IsBoughtAllItems", "IsUnlockByGameId", "IsUnlockByGameIds",
                                              "isUnlockByItem"};
        int num_extra_proto = sizeof(extra_proto_methods) / sizeof(extra_proto_methods[0]);
        for (int ep = 0; ep < num_extra_proto; ep++) {
            // v6.8: 尝试 0-3 参数（修复之前只尝试 0,1 的 BUG）
            Il2CppMethodInfo mi = NULL;
            for (int pc = 0; pc <= 3 && !mi; pc++) {
                mi = fn_class_get_method_from_name(g_proto_login_cls, extra_proto_methods[ep], pc);
            }
            if (!mi) {
                LOGI("[dlc] ProtoLogin.%s not found by name (tried 0-3 params), skip", extra_proto_methods[ep]);
                continue;
            }
            uintptr_t *f = (uintptr_t *)mi;
            if (f[0] == (uintptr_t)custom_return_true_method) {
                LOGI("[dlc] ProtoLogin.%s already patched, skip", extra_proto_methods[ep]);
                continue;
            }
            int pc_found = fn_method_get_param_count ? fn_method_get_param_count(mi) : -1;
            LOGI("[dlc] BEFORE ProtoLogin.%s(%d): mPtr=%p inv=%p name=%p interpData=%p MI=%p",
                 extra_proto_methods[ep], pc_found, (void*)f[0], (void*)f[1], (void*)f[2], (void*)f[10], mi);
            // v6.32: 注册到 Execute hook 目标列表
            execute_hook_add_target(mi);
            uintptr_t page = (uintptr_t)mi & ~(uintptr_t)0xFFF;
            mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE);
            uintptr_t page_end = ((uintptr_t)mi + 0x68) & ~(uintptr_t)0xFFF;
            if (page_end != page) mprotect((void *)page_end, 0x1000, PROT_READ | PROT_WRITE);
            // v6.20: 和 Step 6 一样的修补方式
            f[0]  = (uintptr_t)custom_return_true_method;   // methodPointer
            f[1]  = (uintptr_t)custom_bool_true_invoker;    // invoker_method (0x08)
            // f[2] = name → 不动!
            // v6.33: resolveDatas 是 packed IR 参数，不是指针，不再尝试解引用
            // Execute hook (v6.32) 会拦截这些方法的调用
            f[11] = (uintptr_t)custom_hybridclr_bridge_bool_true;  // methodPointerCallByInterp
            f[12] = (uintptr_t)custom_hybridclr_bridge_bool_true;  // virtualMethodPointerCallByInterp
            // v6.31: 保留 bit5, 只设 bit4
            uint8_t *bf = (uint8_t *)mi + 0x4B;
            *bf = *bf | (1 << 4);
            LOGI("[dlc] ★ ProtoLogin.%s(%d) PATCHED (v6.30) bf=0x%02x interpData=%p MI=%p",
                 extra_proto_methods[ep], pc_found, *bf, (void*)f[10], mi);
            patched++;
        }
        
        // ===== 6a2) v6.8.1: 不再暴力 patch ProtoLogin =====
        // v6.8 暴力 patch 了 IsValidGameItem(2) 导致崩溃
        // IsValidGameItem 不是 unlock 检查，而是数据验证，返回 true 会让游戏访问不存在的数据
        LOGI("[dlc] v6.8.1: Skipping brute-force ProtoLogin patch (caused crash via IsValidGameItem)");

        g_mi_hooks_installed = 1;
        LOGI("[dlc] v6.21 MethodInfo patch complete! %d methods patched (f[0-1]+f[10-12]+bitfield)", patched);
        
        // ===== 6b) v6.27: 恢复 extra class patches (v6.10 水平) =====
        // v6.16 移除了这些 patch 声称"按钮失灵"，但实际上按钮问题是浮窗拦截触摸导致的
        // （v6.18 已通过 FLAG_NOT_TOUCH_MODAL + collapsed 修复）。现在安全恢复。
        {
            struct { const char *cls_name; const char *ns; const char *method_name; int param_count; } extra_patches[] = {
                {"EditorSettingExtension",    "", "get_isUnlockAll",    0},  // v6.28: 恢复! v6.9 有这个
                {"PurchaseUtils",             "", "IsUnlockDianCang",   1},
                {"PurchaseRedPanel",          "", "IsUnlockAllDLC",     1},
                {"PurchaseFriendHelpComponent","", "IsUnlockAll",       0},
                {"PurchaseShopConfig",        "", "IsUnlockAll",        1},
                {"PurchaseShopConfig",        "", "IsUnlockByExtra",    1},
                {"PurchaseRedConfig",         "", "IsUnlockAll",        1},
                {"PackageSystem",             "", "IsUnlockAnyDlc",     1},
                {"PurchasePocketPanel",       "", "isUnlock",            1},
            };
            int num_extra = sizeof(extra_patches) / sizeof(extra_patches[0]);
            int extra_patched = 0;
            
            LOGI("[dlc] ===== Patching extra unlock check classes (v6.27 restored) =====");
            for (int e = 0; e < num_extra; e++) {
                Il2CppClass cls = fn_class_from_name(g_csharp_image, 
                    extra_patches[e].ns, extra_patches[e].cls_name);
                if (!cls) {
                    LOGI("[dlc] Class %s not found, skip", extra_patches[e].cls_name);
                    continue;
                }
                Il2CppMethodInfo mi = fn_class_get_method_from_name(
                    cls, extra_patches[e].method_name, extra_patches[e].param_count);
                if (!mi) {
                    LOGI("[dlc] %s.%s(%d) method not found, skip",
                         extra_patches[e].cls_name, extra_patches[e].method_name,
                         extra_patches[e].param_count);
                    continue;
                }
                
                uintptr_t *f = (uintptr_t *)mi;
                LOGI("[dlc] BEFORE %s.%s: mPtr=%p inv=%p interpData=%p",
                     extra_patches[e].cls_name, extra_patches[e].method_name,
                     (void*)f[0], (void*)f[1], (void*)f[10]);
                
                // v6.32: 注册到 Execute hook 目标列表
                execute_hook_add_target(mi);
                
                uintptr_t pg = (uintptr_t)mi & ~(uintptr_t)0xFFF;
                mprotect((void *)pg, 0x2000, PROT_READ | PROT_WRITE);
                uintptr_t pe = ((uintptr_t)mi + 0x68) & ~(uintptr_t)0xFFF;
                if (pe != pg) mprotect((void *)pe, 0x1000, PROT_READ | PROT_WRITE);
                
                f[0]  = (uintptr_t)custom_return_true_method;
                f[1]  = (uintptr_t)custom_bool_true_invoker;
                // v6.29: 保留 interpData (不清 f[10])
                f[11] = (uintptr_t)custom_hybridclr_bridge_bool_true;
                f[12] = (uintptr_t)custom_hybridclr_bridge_bool_true;
                uint8_t *bf = (uint8_t *)mi + 0x4B;
                *bf = (*bf | (1 << 4)) & ~(1 << 5);  // v6.29: set bit4, clear bit5
                
                LOGI("[dlc] ★ %s.%s PATCHED (v6.29) interpData=%p",
                     extra_patches[e].cls_name, extra_patches[e].method_name, (void*)f[10]);
                extra_patched++;
            }
            LOGI("[dlc] Extra class patches: %d installed", extra_patched);
        }
        
        // ===== 6b2) v6.8.1: 不再暴力 patch 其他类 =====
        // v6.8 暴力 patch 了 IsDownloading, IsPreDownload, IsFilterItem, IsOnlyContainPvPShop 等
        // 这些不是 unlock 检查，返回 true 会导致游戏逻辑错误和崩溃
        LOGI("[dlc] v6.8.1: Skipping brute-force class patches (caused crash via IsDownloading/IsFilterItem/etc)");
        
        // ===== 6b3) v6.9: 移除 PackageSystem 状态修复 =====
        // v6.8 把未下载包设为 Complete(7) 导致游戏加载不存在的资源崩溃
        // 现在让包的真实下载状态保持不变，游戏会正确显示"需要下载"
        LOGI("[dlc] v6.9: Skipping PackageSystem state fix (caused crash loading missing assets)");
        
        // ===== 6c) v6.28: 恢复 EditorSetting.isUnlockAll (v6.9 有此代码) =====
        // EditorSettingExtension 有静态字段 mInstance，通过它获取 EditorSetting 实例
        // 然后将 offset 0x19 处的 bool isUnlockAll 设为 true
        {
            Il2CppClass es_ext_cls = fn_class_from_name(g_csharp_image, "", "EditorSettingExtension");
            if (es_ext_cls) {
                Il2CppMethodInfo m_getInst = fn_class_get_method_from_name(es_ext_cls, "get_Instance", 0);
                if (m_getInst) {
                    void *exc2 = NULL;
                    void *es_inst = NULL;
                    install_sigsegv_handler();
                    g_in_safe_access = 1;
                    if (sigsetjmp(g_jmpbuf, 1) == 0) {
                        es_inst = fn_runtime_invoke(m_getInst, NULL, NULL, &exc2);
                    }
                    g_in_safe_access = 0;
                    uninstall_sigsegv_handler();
                    
                    if (es_inst && !exc2) {
                        LOGI("[dlc] EditorSetting instance: %p", es_inst);
                        // 设置 [0x19] isUnlockAll = true
                        uint8_t *p = (uint8_t *)es_inst;
                        uint8_t old_val = p[0x19];
                        p[0x19] = 1;
                        LOGI("[dlc] ★ EditorSetting.isUnlockAll: %d -> 1", old_val);
                    } else {
                        LOGI("[dlc] EditorSetting.get_Instance() returned NULL or exception");
                    }
                } else {
                    LOGI("[dlc] EditorSetting.get_Instance method not found");
                }
            } else {
                LOGI("[dlc] EditorSettingExtension class not found");
            }
        }

        // ===== 6d) v6.6: 不再 NOP void 方法！让原始方法正常运行 =====
        // v6.5 中 NOP void 方法是错误的：
        // - updatePayBtns: 对已解锁 DLC 会 HIDE 购买按钮，NOP 后按钮保持默认可见
        // - updateUnlock: 显示已解锁的游戏模式，NOP 后小猪妖不可见
        // - UpdateDLCEnter: 设置 DLC 入口，NOP 后 DLC 入口消失
        // 正确做法：让这些方法正常运行，通过 AddDLC 设置正确的 DLC 数据
        // HybridCLR 解释器内部调用会直接读取 mDLCSet 数据
        LOGI("[dlc] v6.6: ===== Keeping void UI methods intact (no NOP) =====");
        LOGI("[dlc] v6.6: updatePayBtns/updateUnlock/UpdateDLCEnter will run with patched DLC data");

        // ===== 6e/6f) v6.17: 跳过 mDLCSet 验证和 EnterLayer dump =====
        // 这些是纯诊断代码，不需要每次运行
        LOGI("[dlc] v6.17: Skipping mDLCSet/EnterLayer diagnostics");
    }
    skip_mi_hook:
    ; // C99/C17 要求 label 后跟语句，不能直接跟声明

    // ===== 7) 验证 hook 效果 =====
    int unlocked_count = 0;
    LOGI("[dlc] === Verification: isUnlockRole via il2cpp_runtime_invoke ===");
    for (int32_t rid = 0; rid <= 15; rid++) {
        void *params[1] = { &rid };
        exc = NULL;
        void *result = NULL;
        SAFE_INVOKE(result, m_isUnlock, (void *)g_proto_login_inst, params, &exc);
        int unlocked = -1;
        if (sigsegv_hit) {
            LOGE("[dlc]   isUnlockRole(%d) SIGSEGV!", rid);
        } else if (exc) {
            LOGE("[dlc]   isUnlockRole(%d) EXCEPTION exc=%p", rid, exc);
        } else if (!result) {
            LOGE("[dlc]   isUnlockRole(%d) result=NULL (no exc, no sigsegv)", rid);
        } else {
            // v6.14-diag: 安全地打印 boxed result 的原始字节
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                uint8_t *rb = (uint8_t *)result;
                LOGI("[dlc]   isUnlockRole(%d) boxed=%p raw: [0x10]=0x%02x [0x11]=0x%02x [0x12]=0x%02x [0x13]=0x%02x klass=%p",
                     rid, result, rb[0x10], rb[0x11], rb[0x12], rb[0x13], *(void**)result);
            } else {
                LOGE("[dlc]   isUnlockRole(%d) SIGSEGV reading boxed result %p", rid, result);
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
            SAFE_UNBOX_INT(unlocked, result, -1);
        }
        LOGI("[dlc]   isUnlockRole(%d) = %d%s", rid, unlocked,
             unlocked > 0 ? " ✓" : " ✗");
        if (unlocked > 0) unlocked_count++;
    }

    // ===== 8) v6.26: 直接操作 mDLCSet (HashSet<int>) =====
    // v6.22 的 AddDLC 调用因 SIGSEGV 失败：AddDLC 是 HybridCLR 解释器方法，
    // 其 interpData(f[10])=0 (延迟初始化)，调用时解释器蹦床读 NULL → 崩溃。
    //
    // 新策略: 绕过 HybridCLR 的 AddDLC 方法，直接操作底层数据结构：
    // 1. 从 ProtoLogin 实例读取 mDLCSet 字段（offset 0x40）
    // 2. mDLCSet 是 HashSet<int>，这是 mscorlib 的 BCL 类，编译为原生 il2cpp 代码
    // 3. 通过 il2cpp_object_get_class 获取 HashSet 类
    // 4. 通过 il2cpp_class_get_method_from_name 找到原生 Add 方法
    // 5. 调用 Add(dlcId) 填充 mDLCSet — 不经过 HybridCLR 解释器
    {
        LOGI("[dlc] v6.26: ===== Direct mDLCSet manipulation =====");
        
        // 读取 mDLCSet 指针 (offset 0x40 from ProtoLogin instance)
        void *dlc_set_obj = NULL;
        install_sigsegv_handler();
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) == 0) {
            dlc_set_obj = *(void **)(g_proto_login_inst + 0x40);
        }
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        
        LOGI("[dlc] v6.26: mDLCSet @ offset 0x40 = %p", dlc_set_obj);

        if (!dlc_set_obj) {
            // mDLCSet 为空，需要创建 HashSet<int> 实例
            // v6.26: 通过字段类型信息获取 HashSet<int> 类，而不是从其他字段猜测
            // 策略: 枚举 ProtoLogin 字段 → 找 mDLCSet → 获取其 Il2CppType → 获取 Il2CppClass
            LOGW("[dlc] v6.26: mDLCSet is NULL, creating via field type info...");
            
            Il2CppClass hashset_int_cls = NULL;
            
            // 方法1: 使用 il2cpp_field_get_type + il2cpp_class_from_il2cpp_type
            if (fn_field_get_type && fn_class_from_type && fn_class_get_fields && fn_field_get_name) {
                void *fiter = NULL;
                Il2CppFieldInfo fi;
                while ((fi = fn_class_get_fields(g_proto_login_cls, &fiter)) != NULL) {
                    const char *fname = fn_field_get_name(fi);
                    if (fname && strcmp(fname, "mDLCSet") == 0) {
                        void *ftype = fn_field_get_type(fi);
                        if (ftype) {
                            hashset_int_cls = fn_class_from_type(ftype);
                            const char *cname = (hashset_int_cls && fn_class_get_name) ? fn_class_get_name(hashset_int_cls) : "(null)";
                            LOGI("[dlc] v6.26: mDLCSet field type → class: %s @ %p", cname, hashset_int_cls);
                        } else {
                            LOGW("[dlc] v6.26: il2cpp_field_get_type returned NULL for mDLCSet");
                        }
                        break;
                    }
                }
            } else {
                LOGW("[dlc] v6.26: Missing APIs: field_get_type=%p class_from_type=%p",
                     fn_field_get_type, fn_class_from_type);
            }
            
            // 方法2 (备选): 扫描所有 ProtoLogin 字段的非空实例寻找 HashSet
            if (!hashset_int_cls) {
                LOGI("[dlc] v6.26: Fallback: scanning ProtoLogin fields for HashSet instance...");
                const int scan_offsets[] = {0x58, 0x48, 0x60, 0x68, 0x70, 0x38, 0x50, 0x30};
                const char *scan_names[] = {"BaseRoles", "mDLCSetInfo", "packAll", "packMagic",
                                            "packClassics", "mRestoreProducts", "mProduct2DLC", "mLoginData"};
                for (int si = 0; si < 8 && !hashset_int_cls; si++) {
                    void *field_obj = NULL;
                    install_sigsegv_handler();
                    g_in_safe_access = 1;
                    if (sigsetjmp(g_jmpbuf, 1) == 0) {
                        field_obj = *(void **)(g_proto_login_inst + scan_offsets[si]);
                    }
                    g_in_safe_access = 0;
                    uninstall_sigsegv_handler();
                    if (!field_obj || (uintptr_t)field_obj < 0x1000) continue;
                    if (fn_object_get_class) {
                        Il2CppClass fcls = fn_object_get_class(field_obj);
                        const char *cname = (fcls && fn_class_get_name) ? fn_class_get_name(fcls) : "(null)";
                        LOGI("[dlc] v6.26:   [0x%02x] %s = %p → class: %s",
                             scan_offsets[si], scan_names[si], field_obj, cname);
                        if (fcls && strstr(cname, "HashSet")) {
                            hashset_int_cls = fcls;
                            LOGI("[dlc] v6.26: ★ Found HashSet template from %s!", scan_names[si]);
                        }
                    }
                }
            }
            
            // 创建 HashSet<int> 实例
            if (hashset_int_cls && fn_object_new) {
                dlc_set_obj = fn_object_new(hashset_int_cls);
                if (dlc_set_obj) {
                    LOGI("[dlc] v6.26: Created HashSet<%s> instance @ %p",
                         fn_class_get_name ? fn_class_get_name(hashset_int_cls) : "?", dlc_set_obj);
                    // 调用 .ctor() 初始化
                    Il2CppMethodInfo ctor = fn_class_get_method_from_name(hashset_int_cls, ".ctor", 0);
                    if (ctor) {
                        uintptr_t *cf = (uintptr_t *)ctor;
                        LOGI("[dlc] v6.26: .ctor MI: f[0]=%p f[10]=%p", (void*)cf[0], (void*)cf[10]);
                        exc = NULL;
                        void *r = NULL;
                        SAFE_INVOKE(r, ctor, dlc_set_obj, NULL, &exc);
                        if (!sigsegv_hit && !exc) {
                            LOGI("[dlc] v6.26: ★ .ctor() OK, writing to mDLCSet field");
                            install_sigsegv_handler();
                            g_in_safe_access = 1;
                            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                                *(void **)(g_proto_login_inst + 0x40) = dlc_set_obj;
                            }
                            g_in_safe_access = 0;
                            uninstall_sigsegv_handler();
                        } else {
                            LOGW("[dlc] v6.26: .ctor() FAILED (sigsegv=%d exc=%p)", sigsegv_hit, exc);
                            dlc_set_obj = NULL;
                        }
                    } else {
                        LOGW("[dlc] v6.26: .ctor(0) not found, writing without init");
                        install_sigsegv_handler();
                        g_in_safe_access = 1;
                        if (sigsetjmp(g_jmpbuf, 1) == 0) {
                            *(void **)(g_proto_login_inst + 0x40) = dlc_set_obj;
                        }
                        g_in_safe_access = 0;
                        uninstall_sigsegv_handler();
                    }
                } else {
                    LOGW("[dlc] v6.26: il2cpp_object_new failed");
                }
            } else if (!hashset_int_cls) {
                LOGW("[dlc] v6.26: Could not determine mDLCSet class type");
            }
        }

        // ===== v6.26: DLCSet 字段填充 =====
        // DLCSet 不是集合类，而是包含 39 个字段的普通对象
        // 每个字段代表一个具体 DLC (YouXiaDLC, XiuNvDLC, NvWuDLC 等)
        // 为 NULL 的字段表示该 DLC 未购买
        // 策略: 遍历所有字段，为每个 NULL 字段创建对应类型的实例
        
        int direct_add_ok = 0;
        int total_fields = 0, null_fields = 0, created_fields = 0;
        int first_nonnull_examined = 0;
        
        if (dlc_set_obj && fn_object_get_class && fn_class_get_fields && fn_field_get_name
            && fn_field_get_offset && fn_field_get_type && fn_class_from_type && fn_object_new) {
            
            Il2CppClass dlcset_cls = fn_object_get_class(dlc_set_obj);
            const char *cls_name = (dlcset_cls && fn_class_get_name) ? fn_class_get_name(dlcset_cls) : "(null)";
            LOGI("[dlc] v6.26: DLCSet class = %s @ %p, populating all NULL fields...", cls_name, dlc_set_obj);
            
            void *fiter = NULL;
            Il2CppFieldInfo fi;
            
            while ((fi = fn_class_get_fields(dlcset_cls, &fiter)) != NULL) {
                const char *fname = fn_field_get_name(fi);
                int foff = fn_field_get_offset ? fn_field_get_offset(fi) : -1;
                if (foff < 16) continue; // skip object header
                
                // 获取字段类型
                void *ftype = fn_field_get_type(fi);
                if (!ftype) continue;
                Il2CppClass *fcls = fn_class_from_type(ftype);
                if (!fcls) continue;
                const char *tname = fn_class_get_name ? fn_class_get_name(fcls) : "?";
                
                total_fields++;
                
                // 读取当前字段值
                void *current_val = NULL;
                install_sigsegv_handler();
                g_in_safe_access = 1;
                if (sigsetjmp(g_jmpbuf, 1) == 0) {
                    current_val = *(void **)((uintptr_t)dlc_set_obj + foff);
                }
                g_in_safe_access = 0;
                uninstall_sigsegv_handler();
                
                if (current_val != NULL) {
                    LOGI("[dlc] v6.26:   %s (off=%d, type=%s): EXISTING %p", fname, foff, tname, current_val);
                    direct_add_ok++;
                    
                    // 检查第一个非空 DLC 子对象的内部结构
                    if (!first_nonnull_examined && fn_class_get_fields && fn_object_get_class) {
                        first_nonnull_examined = 1;
                        Il2CppClass *sub_cls = fn_object_get_class(current_val);
                        const char *sub_name = (sub_cls && fn_class_get_name) ? fn_class_get_name(sub_cls) : "?";
                        LOGI("[dlc] v6.26: ===== Examining DLC sub-type: %s =====", sub_name);
                        
                        // 枚举子对象的字段
                        void *siter = NULL;
                        Il2CppFieldInfo sfi;
                        while ((sfi = fn_class_get_fields(sub_cls, &siter)) != NULL) {
                            const char *sfname = fn_field_get_name(sfi);
                            int sfoff = fn_field_get_offset ? fn_field_get_offset(sfi) : -1;
                            const char *sftype = "(unknown)";
                            if (fn_field_get_type && fn_class_from_type) {
                                void *sft = fn_field_get_type(sfi);
                                if (sft) {
                                    Il2CppClass *sfcls = fn_class_from_type(sft);
                                    if (sfcls && fn_class_get_name) sftype = fn_class_get_name(sfcls);
                                }
                            }
                            // 读取字段值
                            void *sfval = NULL;
                            int32_t sfval_int = 0;
                            install_sigsegv_handler();
                            g_in_safe_access = 1;
                            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                                sfval = *(void **)((uintptr_t)current_val + sfoff);
                                sfval_int = *(int32_t *)((uintptr_t)current_val + sfoff);
                            }
                            g_in_safe_access = 0;
                            uninstall_sigsegv_handler();
                            LOGI("[dlc] v6.26:     F: %s (off=%d, type=%s, val=%p / int=%d)",
                                 sfname, sfoff, sftype, sfval, sfval_int);
                        }
                        
                        // 枚举子对象的方法
                        if (fn_class_get_methods && fn_method_get_name) {
                            void *miter2 = NULL;
                            Il2CppMethodInfo m;
                            while ((m = fn_class_get_methods(sub_cls, &miter2)) != NULL) {
                                const char *mname = fn_method_get_name(m);
                                int pc = fn_method_get_param_count ? fn_method_get_param_count(m) : -1;
                                LOGI("[dlc] v6.26:     M: %s(%d)", mname, pc);
                            }
                        }
                        
                        // 检查父类
                        Il2CppClass *sub_parent = fn_class_get_parent ? fn_class_get_parent(sub_cls) : NULL;
                        if (sub_parent) {
                            const char *spn = fn_class_get_name ? fn_class_get_name(sub_parent) : "?";
                            LOGI("[dlc] v6.26:     Parent: %s", spn);
                        }
                    }
                    continue;
                }
                
                null_fields++;
                
                // 为 NULL 字段创建实例
                void *inst = fn_object_new(fcls);
                if (!inst) {
                    LOGW("[dlc] v6.26:   %s (off=%d, type=%s): object_new FAILED", fname, foff, tname);
                    continue;
                }
                
                // 调用 .ctor(0)
                Il2CppMethodInfo ctor = fn_class_get_method_from_name(fcls, ".ctor", 0);
                if (ctor) {
                    exc = NULL;
                    void *r = NULL;
                    SAFE_INVOKE(r, ctor, inst, NULL, &exc);
                    if (sigsegv_hit || exc) {
                        LOGW("[dlc] v6.26:   %s (off=%d, type=%s): .ctor FAILED (segv=%d exc=%p)",
                             fname, foff, tname, sigsegv_hit, exc);
                        continue;
                    }
                }
                
                // 写入 DLCSet 字段
                install_sigsegv_handler();
                g_in_safe_access = 1;
                if (sigsetjmp(g_jmpbuf, 1) == 0) {
                    *(void **)((uintptr_t)dlc_set_obj + foff) = inst;
                }
                g_in_safe_access = 0;
                uninstall_sigsegv_handler();
                
                if (!sigsegv_hit) {
                    LOGI("[dlc] v6.26:   ★ %s (off=%d, type=%s): CREATED %p", fname, foff, tname, inst);
                    direct_add_ok++;
                    created_fields++;
                } else {
                    LOGW("[dlc] v6.26:   %s (off=%d): write SIGSEGV", fname, foff);
                }
            }
            
            LOGI("[dlc] v6.26: DLCSet population: total=%d, existing=%d, null=%d, created=%d",
                 total_fields, total_fields - null_fields, null_fields, created_fields);
            
        } else if (!dlc_set_obj) {
            LOGW("[dlc] v6.26: mDLCSet is NULL and could not be created");
        } else {
            LOGW("[dlc] v6.26: Missing APIs for DLCSet population");
        }
        
        LOGI("[dlc] v6.26: Direct mDLCSet manipulation: %d items populated", direct_add_ok);
    }
    
    // ===== v6.35: 通过 Execute 直接调用 AddDLC =====
    // v6.22 尝试 il2cpp_runtime_invoke(AddDLC) 失败: bridge 读取 NULL interpData → SIGSEGV
    // 核心发现: Execute 函数内部会处理 NULL interpData (调用 Transform 懒初始化)
    // 所以直接调用 g_orig_execute(AddDLC_MI, stackArgs, NULL) 可以绕过 bridge
    // StackObject 布局: args[0]=this(ptr), args[1]=dlcId(i64)
    if (m_addDLC && g_orig_execute) {
        LOGI("[dlc] v6.35: ===== Calling AddDLC via Execute (bypasses bridge) =====");
        
        // 设置 bypass 防止 AddDLC 被 Execute hook 拦截
        __atomic_store_n(&g_execute_hook_bypass, 1, __ATOMIC_RELEASE);
        
        int add_ok = 0;
        int add_fail = 0;
        for (int32_t dlcId = 1; dlcId <= 50; dlcId++) {
            // HybridCLR StackObject: 8 bytes per slot (union { int64_t i64; void* ptr; })
            // Instance method: args[0] = this, args[1] = param0
            int64_t stack_args[2];
            stack_args[0] = (int64_t)(uintptr_t)g_proto_login_inst;  // this
            stack_args[1] = (int64_t)dlcId;                           // dlcId
            
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                g_orig_execute(m_addDLC, (void*)stack_args, NULL);
                add_ok++;
            } else {
                add_fail++;
                g_in_safe_access = 0;
                uninstall_sigsegv_handler();
                if (add_fail >= 3) {
                    LOGW("[dlc] v6.35: AddDLC SIGSEGV x%d, aborting", add_fail);
                    break;
                }
                continue;
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
        }
        
        __atomic_store_n(&g_execute_hook_bypass, 0, __ATOMIC_RELEASE);
        LOGI("[dlc] v6.35: ★ AddDLC via Execute: %d/50 OK, %d SIGSEGV", add_ok, add_fail);
        
        // 读取 mDLCSet 确认 AddDLC 是否生效
        {
            void *dlc_set_after = NULL;
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                dlc_set_after = *(void **)(g_proto_login_inst + 0x40);
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
            LOGI("[dlc] v6.35: POST-AddDLC: mDLCSet=%p",
                 dlc_set_after);
        }
    } else {
        LOGW("[dlc] v6.35: Cannot call AddDLC via Execute (addDLC=%p, orig_execute=%p)",
             m_addDLC, g_orig_execute);
    }
    
    // ===== v6.35: 注入 mLoginData.DLC 列表 =====
    // 核心发现: DLC 状态来自服务器登录响应 → PlayerPrefs JSON "DLC":[]
    // → mLoginData.DLC (C# List<int>) → mDLCSet → UI
    // 修改内存中的 mLoginData.DLC 列表, 然后调用 UpdateDLC 重建 mDLCSet
    {
        LOGI("[dlc] v6.35: ===== mLoginData.DLC injection =====");
        
        void *login_data = NULL;
        install_sigsegv_handler();
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) == 0) {
            login_data = *(void **)(g_proto_login_inst + 0x30);
        }
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        
        LOGI("[dlc] v6.35: mLoginData @ ProtoLogin+0x30 = %p", login_data);
        
        if (login_data && fn_object_get_class && fn_class_get_fields && fn_field_get_name
            && fn_field_get_offset && fn_field_get_type && fn_class_from_type
            && fn_class_get_name && fn_class_get_method_from_name) {
            
            Il2CppClass login_cls = fn_object_get_class(login_data);
            const char *login_cls_name = login_cls ? fn_class_get_name(login_cls) : "(null)";
            LOGI("[dlc] v6.35: mLoginData class = %s", login_cls_name);
            
            // 枚举 mLoginData 字段, 找 DLC 相关的
            void *fiter = NULL;
            Il2CppFieldInfo fi;
            Il2CppFieldInfo dlc_field = NULL;
            int dlc_field_offset = -1;
            Il2CppClass dlc_field_cls = NULL;
            
            while ((fi = fn_class_get_fields(login_cls, &fiter)) != NULL) {
                const char *fname = fn_field_get_name(fi);
                int foff = fn_field_get_offset ? fn_field_get_offset(fi) : -1;
                void *ftype = fn_field_get_type(fi);
                Il2CppClass fcls = ftype ? fn_class_from_type(ftype) : NULL;
                const char *tname = (fcls && fn_class_get_name) ? fn_class_get_name(fcls) : "?";
                
                // 输出关键字段
                if (fname && (strstr(fname, "DLC") || strstr(fname, "dlc") || 
                    strstr(fname, "Dlc") || strstr(fname, "Gold") ||
                    strstr(fname, "Role") || strstr(fname, "role"))) {
                    LOGI("[dlc] v6.35:   F: %s (off=%d, type=%s)", fname, foff, tname);
                }
                
                // 精确匹配 "DLC" 字段
                if (fname && strcmp(fname, "DLC") == 0) {
                    dlc_field = fi;
                    dlc_field_offset = foff;
                    dlc_field_cls = fcls;
                    LOGI("[dlc] v6.35: ★ Found DLC field: off=%d, type=%s", foff, tname);
                }
            }
            
            if (dlc_field && dlc_field_cls) {
                const char *dlc_type = fn_class_get_name(dlc_field_cls);
                LOGI("[dlc] v6.35: DLC field type: %s", dlc_type);
                
                // 读取当前 DLC 列表对象
                void *dlc_list_obj = NULL;
                install_sigsegv_handler();
                g_in_safe_access = 1;
                if (sigsetjmp(g_jmpbuf, 1) == 0) {
                    dlc_list_obj = *(void **)((uintptr_t)login_data + dlc_field_offset);
                }
                g_in_safe_access = 0;
                uninstall_sigsegv_handler();
                
                LOGI("[dlc] v6.35: DLC list object = %p", dlc_list_obj);
                
                // 获取 List 的实际类 (可能是 List<int>, List<Int32> 等)
                Il2CppClass list_cls = dlc_list_obj ? fn_object_get_class(dlc_list_obj) : dlc_field_cls;
                const char *list_cls_name = (list_cls && fn_class_get_name) ? fn_class_get_name(list_cls) : "?";
                LOGI("[dlc] v6.35: DLC list class = %s @ %p", list_cls_name, list_cls);
                
                if (!dlc_list_obj && list_cls && fn_object_new) {
                    // DLC 列表为空, 创建新 List<int> 实例
                    LOGI("[dlc] v6.35: Creating new DLC list...");
                    dlc_list_obj = fn_object_new(list_cls);
                    if (dlc_list_obj) {
                        Il2CppMethodInfo list_ctor = fn_class_get_method_from_name(list_cls, ".ctor", 0);
                        if (list_ctor) {
                            exc = NULL;
                            void *r = NULL;
                            SAFE_INVOKE(r, list_ctor, dlc_list_obj, NULL, &exc);
                            if (sigsegv_hit || exc) {
                                LOGW("[dlc] v6.35: List .ctor failed, trying bypass...");
                                // 即使 ctor 失败也继续 — il2cpp_object_new 已初始化对象头
                            }
                        }
                        // 写入 mLoginData.DLC 字段
                        install_sigsegv_handler();
                        g_in_safe_access = 1;
                        if (sigsetjmp(g_jmpbuf, 1) == 0) {
                            *(void **)((uintptr_t)login_data + dlc_field_offset) = dlc_list_obj;
                        }
                        g_in_safe_access = 0;
                        uninstall_sigsegv_handler();
                        LOGI("[dlc] v6.35: ★ Created DLC list @ %p, written to mLoginData+0x%x",
                             dlc_list_obj, dlc_field_offset);
                    }
                }
                
                if (dlc_list_obj && list_cls) {
                    // 查找 Add 方法 (List<int>.Add(int))
                    Il2CppMethodInfo m_add = fn_class_get_method_from_name(list_cls, "Add", 1);
                    
                    // 也查找 get_Count 和 Clear
                    Il2CppMethodInfo m_count = fn_class_get_method_from_name(list_cls, "get_Count", 0);
                    Il2CppMethodInfo m_clear = fn_class_get_method_from_name(list_cls, "Clear", 0);
                    
                    LOGI("[dlc] v6.35: List methods: Add=%p, get_Count=%p, Clear=%p",
                         m_add, m_count, m_clear);
                    
                    // 读取当前 count
                    int current_count = -1;
                    if (m_count) {
                        exc = NULL;
                        void *r = NULL;
                        SAFE_INVOKE(r, m_count, dlc_list_obj, NULL, &exc);
                        if (!sigsegv_hit && r) {
                            SAFE_UNBOX_INT(current_count, r, -1);
                        }
                    }
                    LOGI("[dlc] v6.35: Current DLC list count = %d", current_count);
                    
                    // 如果列表已有内容, 先清空
                    if (current_count > 0 && m_clear) {
                        LOGI("[dlc] v6.35: Clearing existing DLC list...");
                        exc = NULL;
                        void *r = NULL;
                        SAFE_INVOKE(r, m_clear, dlc_list_obj, NULL, &exc);
                    }
                    
                    // 添加 DLC ID (1-20)
                    if (m_add) {
                        int list_add_ok = 0;
                        for (int32_t dlcId = 1; dlcId <= 20; dlcId++) {
                            void *params[1] = { &dlcId };
                            exc = NULL;
                            void *r = NULL;
                            SAFE_INVOKE(r, m_add, dlc_list_obj, params, &exc);
                            if (!sigsegv_hit && !exc) {
                                list_add_ok++;
                            } else {
                                LOGW("[dlc] v6.35: List.Add(%d) failed (sigsegv=%d exc=%p)",
                                     dlcId, sigsegv_hit, exc);
                                break;
                            }
                        }
                        LOGI("[dlc] v6.35: ★ mLoginData.DLC: added %d DLC IDs", list_add_ok);
                        
                        // 验证最终 count
                        if (m_count) {
                            exc = NULL;
                            void *r = NULL;
                            SAFE_INVOKE(r, m_count, dlc_list_obj, NULL, &exc);
                            int final_count = -1;
                            if (!sigsegv_hit && r) {
                                SAFE_UNBOX_INT(final_count, r, -1);
                            }
                            LOGI("[dlc] v6.35: Final DLC list count = %d", final_count);
                        }
                    } else {
                        // Add 方法未找到, 尝试直接写 List 内部结构
                        // List<int> 内部: _items (int[] at offset 0x10), _size (int at 0x18)
                        LOGW("[dlc] v6.35: List.Add not found, trying direct _items/_size write...");
                        // 获取 List 的内部结构
                        void *list_fiter = NULL;
                        Il2CppFieldInfo list_fi;
                        int items_off = -1, size_off = -1;
                        Il2CppClass items_cls = NULL;
                        while ((list_fi = fn_class_get_fields(list_cls, &list_fiter)) != NULL) {
                            const char *lfname = fn_field_get_name(list_fi);
                            int lfoff = fn_field_get_offset ? fn_field_get_offset(list_fi) : -1;
                            LOGI("[dlc] v6.35: List field: %s off=%d", lfname, lfoff);
                            if (lfname && strcmp(lfname, "_items") == 0) {
                                items_off = lfoff;
                                void *lft = fn_field_get_type(list_fi);
                                items_cls = lft ? fn_class_from_type(lft) : NULL;
                            }
                            if (lfname && strcmp(lfname, "_size") == 0) size_off = lfoff;
                        }
                        LOGI("[dlc] v6.35: List internal: _items off=%d, _size off=%d", items_off, size_off);
                    }
                }
            } else {
                LOGW("[dlc] v6.35: DLC field not found in %s", login_cls_name);
                // 输出所有字段名帮助诊断
                void *fiter2 = NULL;
                Il2CppFieldInfo fi2;
                LOGI("[dlc] v6.35: All %s fields:", login_cls_name);
                while ((fi2 = fn_class_get_fields(login_cls, &fiter2)) != NULL) {
                    const char *fn2 = fn_field_get_name(fi2);
                    int fo2 = fn_field_get_offset ? fn_field_get_offset(fi2) : -1;
                    LOGI("[dlc] v6.35:   %s (off=%d)", fn2, fo2);
                }
            }
        } else {
            LOGW("[dlc] v6.35: Cannot inspect mLoginData (ptr=%p, APIs missing)", login_data);
        }
    }
    
    // ===== v6.35: 调用 SaveLoginData 持久化修改后的 DLC 数据 =====
    {
        Il2CppMethodInfo m_save = fn_class_get_method_from_name(g_proto_login_cls, "SaveLoginData", 0);
        if (m_save) {
            __atomic_store_n(&g_execute_hook_bypass, 1, __ATOMIC_RELEASE);
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_save, (void*)g_proto_login_inst, NULL, &exc);
            __atomic_store_n(&g_execute_hook_bypass, 0, __ATOMIC_RELEASE);
            if (!sigsegv_hit && !exc) {
                LOGI("[dlc] v6.35: ★ SaveLoginData() OK (persisted DLC data)");
            } else {
                LOGW("[dlc] v6.35: SaveLoginData() failed (sigsegv=%d exc=%p)", sigsegv_hit, exc);
            }
        }
    }
    
    // UpdateDLC 刷新缓存 — v6.35: 使用 bypass 防止 Execute hook 拦截
    {
        Il2CppMethodInfo m_updateDLC = fn_class_get_method_from_name(g_proto_login_cls, "UpdateDLC", 0);
        if (m_updateDLC) {
            __atomic_store_n(&g_execute_hook_bypass, 1, __ATOMIC_RELEASE);
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_updateDLC, (void*)g_proto_login_inst, NULL, &exc);
            __atomic_store_n(&g_execute_hook_bypass, 0, __ATOMIC_RELEASE);
            if (!sigsegv_hit && !exc) {
                LOGI("[dlc] v6.35: ★ UpdateDLC() OK (after AddDLC + mLoginData injection)");
            } else {
                LOGW("[dlc] v6.35: UpdateDLC() failed (sigsegv=%d exc=%p)", sigsegv_hit, exc);
            }
        }
        
        // 读取 mDLCSet 确认 UpdateDLC 效果
        void *post_update_dlcset = NULL;
        install_sigsegv_handler();
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) == 0) {
            post_update_dlcset = *(void **)(g_proto_login_inst + 0x40);
        }
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        LOGI("[dlc] v6.35: POST-UpdateDLC: mDLCSet=%p", post_update_dlcset);
    }

    // ===== v6.29: REAL verification with original invoker =====
    // 上面的 verification (step 7) 用的是 custom_bool_true_invoker, 始终返回 true.
    // 这里临时恢复原始 invoker, 让 fn_runtime_invoke 走原始的 InterpreterInvoke 路径,
    // 执行真实的 IL 代码检查 DLCSet 数据. 这告诉我们 DLCSet 填充是否正确.
    // v6.35: 同时设置 Execute hook bypass, 防止 Execute 层面再次拦截
    int real_unlocked_count = 0;
    if (g_orig_isUnlockRole_invoker && m_isUnlock) {
        LOGI("[dlc] v6.35: ===== REAL isUnlockRole verification (bypass=1) =====");
        uintptr_t *unlock_f = (uintptr_t *)m_isUnlock;
        uintptr_t saved_custom_invoker = unlock_f[1];
        
        // 临时恢复原始 invoker (InterpreterInvoke)
        unlock_f[1] = g_orig_isUnlockRole_invoker;
        // v6.35: 设置 Execute hook bypass, 让调用不被拦截
        __atomic_store_n(&g_execute_hook_bypass, 1, __ATOMIC_RELEASE);
        
        for (int32_t rid = 0; rid <= 15; rid++) {
            void *params[1] = { &rid };
            exc = NULL;
            void *result = NULL;
            SAFE_INVOKE(result, m_isUnlock, (void *)g_proto_login_inst, params, &exc);
            int val = -1;
            if (sigsegv_hit) {
                LOGE("[dlc] v6.35:   REAL isUnlockRole(%d) SIGSEGV!", rid);
            } else if (exc) {
                LOGE("[dlc] v6.35:   REAL isUnlockRole(%d) EXCEPTION", rid);
            } else if (result) {
                SAFE_UNBOX_INT(val, result, -1);
                LOGI("[dlc] v6.35:   REAL isUnlockRole(%d) = %d%s", rid, val, val > 0 ? " ✓" : " ✗");
                if (val > 0) real_unlocked_count++;
            } else {
                LOGI("[dlc] v6.35:   REAL isUnlockRole(%d) result=NULL", rid);
            }
        }
        LOGI("[dlc] v6.35: ★ REAL verification: %d/16 roles (bypass=1, original interpreter)", real_unlocked_count);
        
        // 恢复 Execute hook 拦截 + 自定义 invoker
        __atomic_store_n(&g_execute_hook_bypass, 0, __ATOMIC_RELEASE);
        unlock_f[1] = saved_custom_invoker;
    } else {
        LOGW("[dlc] v6.35: Cannot do REAL verification - original invoker not saved");
    }

    if (unlocked_count >= 10) {
        g_dlc_unlocked = 1;
        LOGI("[dlc] ★ DLC unlock SUCCESS (patched invoker: %d/16, REAL: %d/16)!",
             unlocked_count, real_unlocked_count);
    }

    #undef SAFE_INVOKE
    #undef SAFE_UNBOX_INT

    LOGI("[dlc] ===== DLC unlock v6.35 complete (patched=%d/16, real=%d/16, mi_hooks=%d, exec_hook=%d, targets=%d) =====",
         unlocked_count, real_unlocked_count, g_mi_hooks_installed, g_execute_hook_installed, g_execute_hook_target_count);
    return unlocked_count;
}
/* v6.17: 以下旧的诊断代码已禁用 */
#if 0
        Il2CppMethodInfo m_getDLCId = fn_class_get_method_from_name(g_proto_login_cls, "GetDLCId", 1);
        if (m_getDLCId) {
            LOGI("[dlc] v6.7: ===== GetDLCId mapping (PackageEnum → DLC ID) =====");
            for (int32_t pe = 0; pe <= 30; pe++) {
                void *params[1] = { &pe };
                exc = NULL;
                void *r = NULL;
                SAFE_INVOKE(r, m_getDLCId, (void*)g_proto_login_inst, params, &exc);
                int dlcId = -1;
                if (!sigsegv_hit && r) { SAFE_UNBOX_INT(dlcId, r, -1); }
                if (dlcId > 0) {
                    LOGI("[dlc] v6.7:   PackageEnum(%d) → DLC ID %d", pe, dlcId);
                }
            }
        }
        // 同样调用 GetProductId
        Il2CppMethodInfo m_getProductId = fn_class_get_method_from_name(g_proto_login_cls, "GetProductId", 1);
        if (m_getProductId) {
            LOGI("[dlc] v6.7: ===== GetProductId mapping =====");
            for (int32_t pe = 0; pe <= 30; pe++) {
                void *params[1] = { &pe };
                exc = NULL;
                void *r = NULL;
                SAFE_INVOKE(r, m_getProductId, (void*)g_proto_login_inst, params, &exc);
                // ProductId 是 string，result 是 Il2CppString*
                if (!sigsegv_hit && r) {
                    LOGI("[dlc] v6.7:   PackageEnum(%d) → ProductId=%p", pe, r);
                }
            }
        }
    }

    // v6.7: 设置验证完成标志，之后 custom_return_true_method 的调用来自解释器
    g_verification_complete = 1;
    LOGI("[dlc] v6.7: g_verification_complete=1, now tracking interpreter calls to custom_return_true");

    if (m_addDLC) {
        int add_ok = 0;
        for (int32_t dlcId = 1; dlcId <= 50; dlcId++) {
            void *params[1] = { &dlcId };
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_addDLC, (void *)g_proto_login_inst, params, &exc);
            if (sigsegv_hit) break;
            if (!exc) add_ok++;
        }
        LOGI("[dlc] AddDLC(1-50): %d OK", add_ok);
    }

    // ===== 8b) v6.6: 扩展 DLC ID 范围，添加更多可能的 DLC ID =====
    if (m_addDLC) {
        int add_ok2 = 0;
        // 某些 DLC ID 可能大于 50（如 100, 200, 1000 等）
        int extra_dlc_ids[] = {100, 101, 102, 103, 104, 105, 110, 120, 150, 
                               200, 201, 202, 203, 204, 205, 210, 220, 250, 
                               300, 301, 302, 303, 400, 500, 1000, 1001, 1002,
                               2000, 2001, 2002, 3000, 3001, 5000, 10000};
        for (int i = 0; i < (int)(sizeof(extra_dlc_ids)/sizeof(extra_dlc_ids[0])); i++) {
            int32_t dlcId = extra_dlc_ids[i];
            void *params[1] = { &dlcId };
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_addDLC, (void *)g_proto_login_inst, params, &exc);
            if (sigsegv_hit) break;
            if (!exc) add_ok2++;
        }
        LOGI("[dlc] v6.6: AddDLC(extra IDs): %d OK", add_ok2);
    }

    // ===== 8c) v6.6: 调用 UpdateDLC 触发 DLC 状态重新计算 =====
    {
        Il2CppMethodInfo m_updateDLC = fn_class_get_method_from_name(g_proto_login_cls, "UpdateDLC", 0);
        if (m_updateDLC) {
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_updateDLC, (void*)g_proto_login_inst, NULL, &exc);
            if (!sigsegv_hit && !exc) {
                LOGI("[dlc] v6.6: ★ UpdateDLC() called successfully");
            } else {
                LOGI("[dlc] v6.6: UpdateDLC() failed (sigsegv=%d exc=%p)", sigsegv_hit, exc);
            }
        } else {
            LOGI("[dlc] v6.6: UpdateDLC method not found");
        }
    }

    // ===== 8d) v6.6: 调用 SaveLoginData 持久化 DLC 数据 =====
    {
        Il2CppMethodInfo m_save = fn_class_get_method_from_name(g_proto_login_cls, "SaveLoginData", 0);
        if (m_save) {
            exc = NULL;
            void *r = NULL;
            SAFE_INVOKE(r, m_save, (void*)g_proto_login_inst, NULL, &exc);
            if (!sigsegv_hit && !exc) {
                LOGI("[dlc] v6.6: ★ SaveLoginData() called successfully");
            } else {
                LOGI("[dlc] v6.6: SaveLoginData() failed (sigsegv=%d exc=%p)", sigsegv_hit, exc);
            }
        }
    }

    // ===== 8e2) v6.7: 调用 GetDLCs() 查看当前 DLC 集合 =====
    {
        Il2CppMethodInfo m_getDLCs = fn_class_get_method_from_name(g_proto_login_cls, "GetDLCs", 0);
        if (m_getDLCs) {
            exc = NULL;
            void *dlcs_result = NULL;
            SAFE_INVOKE(dlcs_result, m_getDLCs, (void*)g_proto_login_inst, NULL, &exc);
            LOGI("[dlc] v6.7: GetDLCs() = %p (exc=%p sigsegv=%d)", dlcs_result, exc, sigsegv_hit);
        }
        // 再读一次 mDLCSet 验证是否被 AddDLC 填充
        uint8_t *inst = (uint8_t *)g_proto_login_inst;
        uintptr_t dlcSet = *(uintptr_t *)(inst + 64);
        uintptr_t dlcSetInfo = *(uintptr_t *)(inst + 72);
        LOGI("[dlc] v6.7: POST-AddDLC: mDLCSet=%p mDLCSetInfo=%p", (void*)dlcSet, (void*)dlcSetInfo);
        if (dlcSet) {
            install_sigsegv_handler();
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) == 0) {
                // 尝试读取 HashSet 的 klass name
                uintptr_t klass = *(uintptr_t *)dlcSet;
                if (klass) {
                    const char *kname = fn_class_get_name ? fn_class_get_name((void*)klass) : "?";
                    LOGI("[dlc] v6.7:   mDLCSet klass=%p name=%s", (void*)klass, kname ? kname : "null");
                }
                // 读取几个偏移找 count
                for (int off = 0x18; off <= 0x50; off += 8) {
                    int32_t v = *(int32_t *)((uint8_t *)dlcSet + off);
                    if (v > 0 && v < 10000) {
                        LOGI("[dlc] v6.7:   mDLCSet[0x%x] = %d (possible count)", off, v);
                    }
                }
            }
            g_in_safe_access = 0;
            uninstall_sigsegv_handler();
        }
    }

    // ===== 8e) v6.6: 验证关键 DLC 检查方法的返回值 =====
    // 注意: 这些方法已被补丁为 return true，所以这里验证的是 invoker 层面
    // 真正的验证需要看 HybridCLR 解释器内部调用的结果
    {
        const char *check_methods[] = {"IsDianCang", "IsUnlockGuBao", "IsOldPlayer", "IsBoughtAllItems"};
        for (int cm = 0; cm < 4; cm++) {
            Il2CppMethodInfo m_check = fn_class_get_method_from_name(g_proto_login_cls, check_methods[cm], 
                (strcmp(check_methods[cm], "IsOldPlayer") == 0 || strcmp(check_methods[cm], "IsBoughtAllItems") == 0) ? 0 : 1);
            if (m_check) {
                int32_t arg = 0;
                void *params[1] = { &arg };
                void *nparams = (strcmp(check_methods[cm], "IsOldPlayer") == 0 || 
                                 strcmp(check_methods[cm], "IsBoughtAllItems") == 0) ? NULL : params;
                exc = NULL;
                void *r = NULL;
                SAFE_INVOKE(r, m_check, (void*)g_proto_login_inst, nparams, &exc);
                int val = -1;
                if (!sigsegv_hit && r) { SAFE_UNBOX_INT(val, r, -1); }
                LOGI("[dlc] v6.6:   %s() = %d (via invoke, patched=%s)", 
                     check_methods[cm], val,
                     (*(uintptr_t*)m_check == (uintptr_t)custom_return_true_method) ? "YES" : "NO");
            }
        }
    }

    // ===== 9) 尝试找 get_DLCSetInfo 方法并调用（触发缓存更新）=====
    {
        Il2CppMethodInfo m_getDSI = fn_class_get_method_from_name(g_proto_login_cls, "get_DLCSetInfo", 0);
        if (m_getDSI) {
            exc = NULL;
            void *dsi_result = NULL;
            SAFE_INVOKE(dsi_result, m_getDSI, (void*)g_proto_login_inst, NULL, &exc);
            if (!sigsegv_hit && dsi_result) {
                // dsi_result 是 boxed 结果或直接对象引用
                LOGI("[dlc] get_DLCSetInfo() returned %p", dsi_result);
            } else {
                LOGI("[dlc] get_DLCSetInfo() returned NULL or SIGSEGV");
            }
        } else {
            LOGI("[dlc] get_DLCSetInfo method not found");
        }
    }

    // ===== 10) 枚举 ProtoLogin 所有方法，找与 unlock/role/dlc 相关的 =====
    if (verbose && fn_class_get_methods && fn_method_get_name && fn_method_get_param_count) {
        LOGI("[dlc] ===== ProtoLogin methods scan =====");
        void *iter = NULL;
        Il2CppMethodInfo m;
        while ((m = fn_class_get_methods(g_proto_login_cls, &iter)) != NULL) {
            const char *name = fn_method_get_name(m);
            if (!name) continue;
            int params = fn_method_get_param_count(m);
            
            // 过滤: 只输出与 unlock/role/dlc/purchase/buy 相关的方法
            if (strstr(name, "nlock") || strstr(name, "ock") ||
                strstr(name, "role") || strstr(name, "Role") ||
                strstr(name, "dlc") || strstr(name, "DLC") ||
                strstr(name, "urchase") || strstr(name, "uy") ||
                strstr(name, "set_") || strstr(name, "get_") ||
                strstr(name, "Update") || strstr(name, "Login") ||
                strstr(name, "Init") || strstr(name, "Base")) {
                uintptr_t mptr = *(uintptr_t *)m;
                LOGI("[dlc-methods] %s(%d) ptr=%p MI=%p", name, params, (void*)mptr, m);
            }
        }
    }

#endif /* v6.17 disabled */

/* v6.17: 上面的 #if 0 块中已包含旧的 return 逻辑，不需要额外的 } */

// ========== RoleInfo 实例缓存（避免每次全量扫描）==========
#define MAX_CACHED_ROLEINFO 8
static uintptr_t g_cached_roleinfo[MAX_CACHED_ROLEINFO];
static int        g_cached_count = 0;

// ========== RoleInfoToWar 实例缓存 ==========
#define MAX_CACHED_WARINFO 8
static uintptr_t g_cached_warinfo[MAX_CACHED_WARINFO];
static int        g_warinfo_count = 0;

// 验证缓存的 RoleInfo 地址是否仍然有效
static int validate_cached_roleinfo(void) {
    if (g_cached_count == 0) return 0;
    
    uintptr_t klass_val = (uintptr_t)g_roleinfo_cls;
    int valid = 0;
    
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) {
            g_in_safe_access = 0;
            continue; // 地址无效，跳过
        }
        // 验证 klass 指针
        uintptr_t klass = *(volatile uintptr_t *)obj;
        if (klass != klass_val) { g_in_safe_access = 0; continue; }
        // 验证 roleId
        int32_t roleId = *(volatile int32_t *)(obj + 0x10);
        if (roleId < 0 || roleId > 200) { g_in_safe_access = 0; continue; }
        g_in_safe_access = 0;
        // 仍然有效，保留
        g_cached_roleinfo[valid++] = obj;
    }
    uninstall_sigsegv_handler();
    
    g_cached_count = valid;
    return valid;
}

// 全量扫描并更新缓存
static int scan_and_cache_roleinfo(void) {
    g_cached_count = 0;
    parse_maps();
    uintptr_t klass_val = (uintptr_t)g_roleinfo_cls;
    install_sigsegv_handler();
    
    for (int r = 0; r < g_region_count && g_cached_count < MAX_CACHED_ROLEINFO; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        size_t size = region->end - region->start;
        if (size < 0x100 || size > MAX_SCAN_SIZE) continue;
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;
        
        uint8_t *base = (uint8_t *)region->start;
        for (size_t off = 0; off <= size - 0x100 && g_cached_count < MAX_CACHED_ROLEINFO; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; break; }
            
            uintptr_t *p = (uintptr_t *)(base + off);
            if (*p != klass_val) { g_in_safe_access = 0; continue; }
            
            uintptr_t obj_addr = (uintptr_t)(base + off);
            uintptr_t monitor = *(volatile uintptr_t *)(obj_addr + 8);
            if (monitor != 0 && monitor < 0x10000) { g_in_safe_access = 0; continue; }
            int32_t roleId = *(volatile int32_t *)(obj_addr + 0x10);
            if (roleId < 0 || roleId > 200) { g_in_safe_access = 0; continue; }
            int32_t maxHp = *(volatile int32_t *)(obj_addr + 0x14);
            if (maxHp < 0 || maxHp > 99999) { g_in_safe_access = 0; continue; }
            int32_t curHp = *(volatile int32_t *)(obj_addr + 0x18);
            if (curHp < 0 || curHp > 99999) { g_in_safe_access = 0; continue; }
            int32_t level = *(volatile int32_t *)(obj_addr + 0x24);
            if (level < 0 || level > 100) { g_in_safe_access = 0; continue; }
            g_in_safe_access = 0;
            
            LOGI("RoleInfo @ 0x%" PRIxPTR ": roleId=%d level=%d HP=%d/%d",
                 obj_addr, roleId, level, curHp, maxHp);
            g_cached_roleinfo[g_cached_count++] = obj_addr;
        }
    }
    
    uninstall_sigsegv_handler();
    LOGI("scan_and_cache: found %d RoleInfo instance(s)", g_cached_count);
    return g_cached_count;
}

// 获取有效的 RoleInfo 地址列表（优先用缓存，失效则重新扫描）
static int ensure_roleinfo_cached(void) {
    int valid = validate_cached_roleinfo();
    if (valid > 0) {
        LOGI("Cache hit: %d valid RoleInfo instance(s)", valid);
        return valid;
    }
    LOGI("Cache miss, doing full scan...");
    return scan_and_cache_roleinfo();
}

// ========== RoleInfoToWar 实例扫描与缓存 ==========
// RoleInfoToWar 字段布局:
//   [0x10] Int32 hp       [0x14] Int32 maxHp
//   [0x18] Int32 mp       [0x1c] Int32 action
//   [0x20] Int32 level    [0x24] Int32 maxHandCard
//   [0x50] List<Int32> cards
//   [0x58] List<Int32> initCards
//   [0x60] List<Int32> equipts  <-- 战斗装备列表
//   [0x68] List<CardInfo> enemySkills
//   [0x70] List<UserSkillState> heroSkills
//   [0x78] List<EventBuffStr> buffs

static int scan_and_cache_warinfo(void) {
    g_warinfo_count = 0;
    if (!g_warinfo_cls) return 0;
    parse_maps();
    uintptr_t klass_val = (uintptr_t)g_warinfo_cls;
    install_sigsegv_handler();
    
    for (int r = 0; r < g_region_count && g_warinfo_count < MAX_CACHED_WARINFO; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        size_t size = region->end - region->start;
        if (size < 0x80 || size > MAX_SCAN_SIZE) continue;
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;
        
        uint8_t *base = (uint8_t *)region->start;
        for (size_t off = 0; off <= size - 0x80 && g_warinfo_count < MAX_CACHED_WARINFO; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; break; }
            
            uintptr_t *p = (uintptr_t *)(base + off);
            if (*p != klass_val) { g_in_safe_access = 0; continue; }
            
            uintptr_t obj_addr = (uintptr_t)(base + off);
            // 验证: hp, maxHp, mp, action, level 应合理
            int32_t hp = *(volatile int32_t *)(obj_addr + 0x10);
            int32_t maxHp = *(volatile int32_t *)(obj_addr + 0x14);
            int32_t level = *(volatile int32_t *)(obj_addr + 0x20);
            if (hp < 0 || hp > 999999) { g_in_safe_access = 0; continue; }
            if (maxHp < 0 || maxHp > 999999) { g_in_safe_access = 0; continue; }
            if (level < 0 || level > 100) { g_in_safe_access = 0; continue; }
            g_in_safe_access = 0;
            
            LOGI("RoleInfoToWar @ 0x%" PRIxPTR ": hp=%d/%d level=%d",
                 obj_addr, hp, maxHp, level);
            g_cached_warinfo[g_warinfo_count++] = obj_addr;
        }
    }
    
    uninstall_sigsegv_handler();
    LOGI("scan_and_cache_warinfo: found %d RoleInfoToWar instance(s)", g_warinfo_count);
    return g_warinfo_count;
}

static int validate_cached_warinfo(void) {
    if (g_warinfo_count == 0) return 0;
    if (!g_warinfo_cls) return 0;
    
    uintptr_t klass_val = (uintptr_t)g_warinfo_cls;
    int valid = 0;
    
    install_sigsegv_handler();
    for (int i = 0; i < g_warinfo_count; i++) {
        uintptr_t obj = g_cached_warinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t klass = *(volatile uintptr_t *)obj;
        if (klass != klass_val) { g_in_safe_access = 0; continue; }
        int32_t hp = *(volatile int32_t *)(obj + 0x10);
        if (hp < 0 || hp > 999999) { g_in_safe_access = 0; continue; }
        g_in_safe_access = 0;
        g_cached_warinfo[valid++] = obj;
    }
    uninstall_sigsegv_handler();
    
    g_warinfo_count = valid;
    return valid;
}

static int ensure_warinfo_cached(void) {
    int valid = validate_cached_warinfo();
    if (valid > 0) {
        LOGI("WarInfo cache hit: %d valid instance(s)", valid);
        return valid;
    }
    LOGI("WarInfo cache miss, scanning...");
    return scan_and_cache_warinfo();
}

// ========== 修改金币（返回修改的实例数）==========
static int do_modify_gold(int target_gold) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        int32_t *gold_ptr = (int32_t *)(obj_addr + 0x2c);
        int32_t old_gold = *gold_ptr;
        *gold_ptr = target_gold;
        g_in_safe_access = 0;
        count++;
        LOGI("  => Gold: %d -> %d @ 0x%" PRIxPTR, old_gold, target_gold, obj_addr);
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_gold: modified %d instance(s)", count);
    return count;
}

// ========== 重置所有技能 CD（返回重置的技能数）==========
// 扫描 RoleInfo 偏移 0x78-0xB0，覆盖探索技能、战斗技能等
static int do_reset_skill_cd(void) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        
        // 扫描 RoleInfo 偏移 0x78-0xB0 的所有指针字段
        // 已知: dungeonSkill(0x80), skills(0x88)
        // 扩展扫描以覆盖可能的战斗技能字段
        for (int off = 0x78; off <= 0xB0; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) {
                g_in_safe_access = 0;
                continue; // 该偏移访问出错，跳到下一个
            }
            
            uintptr_t ptr = *(volatile uintptr_t *)(obj_addr + off);
            if (ptr < 0x10000) { g_in_safe_access = 0; continue; }
            
            // --- 尝试作为单个技能对象: id(+0x10), cd(+0x14) ---
            int32_t sid = *(volatile int32_t *)(ptr + 0x10);
            int32_t scd = *(volatile int32_t *)(ptr + 0x14);
            if (sid >= 0 && sid < 10000 && scd > 0 && scd < 10000) {
                LOGI("  => Skill @+0x%x id=%d CD: %d -> 0", off, sid, scd);
                *(int32_t *)(ptr + 0x14) = 0;
                count++;
                g_in_safe_access = 0;
                continue; // 已作为单技能处理
            }
            
            // --- 尝试作为 List<Skill>: _items(+0x10), _size(+0x18) ---
            uintptr_t items = *(volatile uintptr_t *)(ptr + 0x10);
            int32_t sz = *(volatile int32_t *)(ptr + 0x18);
            if (items < 0x10000 || sz <= 0 || sz >= 100) {
                g_in_safe_access = 0; continue;
            }
            for (int si = 0; si < sz; si++) {
                uintptr_t sk = *(volatile uintptr_t *)(items + 0x20 + si * sizeof(void*));
                if (sk < 0x10000) continue;
                int32_t *cd_ptr = (int32_t *)(sk + 0x14);
                if (*cd_ptr > 0 && *cd_ptr < 10000) {
                    int32_t sk_id = *(int32_t *)(sk + 0x10);
                    if (sk_id >= 0 && sk_id < 10000) {
                        LOGI("  => List[+0x%x][%d] id=%d CD: %d -> 0",
                             off, si, sk_id, *cd_ptr);
                        *cd_ptr = 0; count++;
                    }
                }
            }
            g_in_safe_access = 0;
        }
    }
    uninstall_sigsegv_handler();
    LOGI("do_reset_skill_cd: reset %d skill(s)", count);
    return count;
}

// ========== 修改血量上限和当前血量 ==========
static int do_modify_hp(int max_hp) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        int32_t old_maxhp = *(int32_t *)(obj_addr + OFF_MAXHP);
        int32_t old_curhp = *(int32_t *)(obj_addr + OFF_CURHP);
        *(int32_t *)(obj_addr + OFF_MAXHP) = max_hp;
        *(int32_t *)(obj_addr + OFF_CURHP) = max_hp; // 回满血
        g_in_safe_access = 0;
        count++;
        LOGI("  => HP: %d/%d -> %d/%d @ 0x%" PRIxPTR, old_curhp, old_maxhp, max_hp, max_hp, obj_addr);
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_hp: modified %d instance(s)", count);
    return count;
}

// ========== 修改法力值 ==========
static int do_modify_mp(int mp) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        int32_t old_mp = *(int32_t *)(obj_addr + OFF_CURMP);
        *(int32_t *)(obj_addr + OFF_CURMP) = mp;
        g_in_safe_access = 0;
        count++;
        LOGI("  => MP: %d -> %d @ 0x%" PRIxPTR, old_mp, mp, obj_addr);
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_mp: modified %d instance(s)", count);
    return count;
}

// ========== 修改行动值 ==========
static int do_modify_action(int action) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        int32_t old_action = *(int32_t *)(obj_addr + OFF_CURACTION);
        *(int32_t *)(obj_addr + OFF_CURACTION) = action;
        g_in_safe_access = 0;
        count++;
        LOGI("  => Action: %d -> %d @ 0x%" PRIxPTR, old_action, action, obj_addr);
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_action: modified %d instance(s)", count);
    return count;
}

// ========== 修改手牌上限 ==========
static int do_modify_handcards(int handcards) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        int32_t old_handcards = *(int32_t *)(obj_addr + OFF_HANDCARDS);
        *(int32_t *)(obj_addr + OFF_HANDCARDS) = handcards;
        g_in_safe_access = 0;
        count++;
        LOGI("  => Handcards: %d -> %d @ 0x%" PRIxPTR, old_handcards, handcards, obj_addr);
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_handcards: modified %d instance(s)", count);
    return count;
}

// ========== 向 List<Int32> 添加物品 ID ==========
// il2cpp List<int> 内存布局:
//   +0x00 klass ptr
//   +0x08 monitor
//   +0x10 _items (System.Int32[] 数组指针)
//   +0x18 _size (int32)
// System.Int32[] (SZArray) 数组布局:
//   +0x00 klass ptr
//   +0x08 monitor
//   +0x10 bounds (= NULL for SZArray)
//   +0x18 max_length (nint, 8 bytes on ARM64)
//   +0x20 elements[] (int32)

// 手动分配一个 Il2CppSZArray(Int32[]) —— 当原数组容量不够时用
// 复制 klass/monitor 头部，重设 max_length，拷贝旧元素
// 返回新数组指针 (mmap 分配, 不会被 GC 回收, 故意 leak)
// compact=0: 标准SZArray - bounds(+0x10)=NULL, max_len(+0x18), elem(+0x20)
// compact=1: 紧凑SZArray - max_len(+0x10), elem(+0x18), 无bounds字段
static uintptr_t alloc_int32_szarray(uintptr_t old_arr, int new_cap, int compact) {
    size_t header_sz = compact ? 0x18 : 0x20;
    size_t total = header_sz + (size_t)new_cap * 4;
    size_t page_sz = 4096;
    size_t alloc_sz = (total + page_sz - 1) & ~(page_sz - 1);
    void *mem = mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("  alloc_szarray: mmap failed (size=%zu)", alloc_sz);
        return 0;
    }
    memset(mem, 0, alloc_sz);
    uintptr_t arr = (uintptr_t)mem;

    if (old_arr > 0x10000) {
        *(volatile uintptr_t *)(arr + 0x00) = *(volatile uintptr_t *)(old_arr + 0x00);
        *(volatile uintptr_t *)(arr + 0x08) = *(volatile uintptr_t *)(old_arr + 0x08);
    }
    if (compact) {
        *(volatile uintptr_t *)(arr + 0x10) = (uintptr_t)new_cap;
    } else {
        *(volatile uintptr_t *)(arr + 0x10) = 0; // bounds=NULL
        *(volatile uintptr_t *)(arr + 0x18) = (uintptr_t)new_cap;
    }

    LOGI("  alloc_szarray: @ %p, cap=%d, %s", mem, new_cap, compact ? "compact" : "standard");
    return arr;
}

static int add_item_to_int_list(uintptr_t list_ptr, int item_id) {
    if (list_ptr < 0x10000) { LOGW("  add_item: list_ptr invalid (%p)", (void*)list_ptr); return -1; }
    
    uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
    int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
    
    if (items < 0x10000 || size < 0 || size > 1000) {
        LOGW("  add_item: invalid list (items=%p, size=%d)", (void*)items, size);
        return -1;
    }
    
    // 探测 SZArray 布局: bounds at +0x10, max_length at +0x18, elements at +0x20
    uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
    uintptr_t max_length;
    int32_t *elem_base;
    int is_standard_layout = 0; // bounds=NULL 标准布局
    
    if (probe == 0) {
        // 标准 SZArray: bounds=NULL, max_length at +0x18, elements at +0x20
        max_length = *(volatile uintptr_t *)(items + 0x18);
        elem_base = (int32_t *)(items + 0x20);
        is_standard_layout = 1;
    } else if (probe > 0 && probe <= 200000) {
        // 无 bounds 字段, +0x10 直接是 max_length, elements at +0x18
        max_length = probe;
        elem_base = (int32_t *)(items + 0x18);
    } else {
        // 检查低32位是否为合理的 max_length
        uint32_t lo32 = (uint32_t)(probe & 0xFFFFFFFF);
        if (lo32 > 0 && lo32 <= 200000) {
            max_length = lo32;
            elem_base = (int32_t *)(items + 0x18);
        } else {
            max_length = *(volatile uintptr_t *)(items + 0x18);
            elem_base = (int32_t *)(items + 0x20);
            is_standard_layout = 1;
        }
    }
    
    LOGI("  add_item: id=%d, list size=%d, arr cap=%d, layout=%s, elem_base=%p",
         item_id, size, (int)max_length,
         is_standard_layout ? "standard(bounds=NULL)" : "compact",
         (void*)elem_base);
    
    // 容量不够时 → 分配新数组并替换
    if (max_length == 0 || (uintptr_t)size >= max_length) {
        int new_cap = (int)(max_length == 0 ? 16 : max_length * 2);
        if (new_cap < size + 4) new_cap = size + 4;
        if (new_cap > 2000) new_cap = 2000;
        
        LOGI("  Expanding: old cap=%d, new cap=%d, copying %d elements",
             (int)max_length, new_cap, size);
        
        int compact = !is_standard_layout;
        uintptr_t new_arr = alloc_int32_szarray(items, new_cap, compact);
        if (!new_arr) return -1;
        
        // 拷贝旧元素到新数组 (偏移取决于布局)
        int32_t *new_elem = (int32_t *)(new_arr + (compact ? 0x18 : 0x20));
        for (int i = 0; i < size; i++) {
            new_elem[i] = elem_base[i];
        }
        
        // 替换 List._items 指针
        *(volatile uintptr_t *)(list_ptr + 0x10) = new_arr;
        
        // 更新本地变量指向新数组
        items = new_arr;
        elem_base = new_elem;
        max_length = (uintptr_t)new_cap;
        
        LOGI("  Replaced _items: old=%p -> new=%p", (void*)(*(volatile uintptr_t *)(list_ptr + 0x10)), (void*)new_arr);
    }
    
    if ((int64_t)max_length <= 0 || max_length > 10000 || (int64_t)max_length < size) {
        LOGW("  add_item: bad capacity (%d), size=%d", (int)max_length, size);
        return -1;
    }
    
    // 添加到末尾
    elem_base[size] = item_id;
    *(int32_t *)(list_ptr + 0x18) = size + 1;
    LOGI("  Added item %d to list (size: %d -> %d)", item_id, size, size + 1);
    return 1;
}

// ========== 添加装备到装备栏 ==========
// 优先找空槽(value=0)填入, 无空槽则追加新槽
// 双写: RoleInfo.equipmentSlot(0x98) + RoleInfoToWar.equipts(0x60)
static int do_add_equipment(int equip_id) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        
        uintptr_t equip_list = *(volatile uintptr_t *)(obj_addr + OFF_EQUIPSLOT);
        if (equip_list < 0x10000) { g_in_safe_access = 0; continue; }
        
        uintptr_t items = *(volatile uintptr_t *)(equip_list + 0x10);
        int32_t size = *(volatile int32_t *)(equip_list + 0x18);
        
        if (items < 0x10000 || size < 0 || size > 100) { g_in_safe_access = 0; continue; }
        
        // 探测 SZArray 布局
        uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
        int32_t *elem_base;
        if (probe == 0) {
            elem_base = (int32_t *)(items + 0x20);
        } else if (probe > 0 && probe <= 200000) {
            elem_base = (int32_t *)(items + 0x18);
        } else {
            elem_base = (int32_t *)(items + 0x20);
        }
        
        LOGI("  equip slot: size=%d, looking for empty slot for equip %d", size, equip_id);
        
        // 寻找空槽 (value=0) 填入装备
        int found = 0;
        for (int s = 0; s < size; s++) {
            if (elem_base[s] == 0) {
                elem_base[s] = equip_id;
                LOGI("  Filled empty slot [%d] with equip %d", s, equip_id);
                found = 1;
                break;
            }
        }
        
        // 无空槽则追加 (创建新槽)
        if (!found) {
            int ret = add_item_to_int_list(equip_list, equip_id);
            if (ret > 0) {
                LOGI("  Appended new slot with equip %d (size: %d -> %d)", equip_id, size, size + 1);
                found = 1;
            }
        }
        
        g_in_safe_access = 0;
        if (found) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_add_equipment: added equip %d to %d RoleInfo instance(s)", equip_id, count);
    
    // ====== 同步写入 RoleInfoToWar.equipts(0x60) ======
    int war_count = ensure_warinfo_cached();
    if (war_count > 0) {
        int wc = 0;
        install_sigsegv_handler();
        for (int i = 0; i < g_warinfo_count; i++) {
            uintptr_t wobj = g_cached_warinfo[i];
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            
            uintptr_t war_equip_list = *(volatile uintptr_t *)(wobj + 0x60);
            g_in_safe_access = 0;
            
            if (war_equip_list > 0x10000) {
                int ret = add_item_to_int_list(war_equip_list, equip_id);
                if (ret >= 0) {
                    wc++;
                    LOGI("  Also added equip %d to RoleInfoToWar.equipts @ %p", equip_id, (void*)wobj);
                }
            } else {
                LOGW("  RoleInfoToWar @ %p: equipts list is NULL/invalid (%p)", (void*)wobj, (void*)war_equip_list);
            }
        }
        uninstall_sigsegv_handler();
        LOGI("do_add_equipment: synced equip %d to %d RoleInfoToWar instance(s)", equip_id, wc);
    } else {
        LOGI("do_add_equipment: no RoleInfoToWar instances found (not in battle?)");
    }
    
    return count;
}

// ========== 添加遗物/祝福 ==========
static int do_add_lostthing(int lostthing_id) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t lt_list = *(volatile uintptr_t *)(obj_addr + OFF_LOSTTHING);
        int ret = add_item_to_int_list(lt_list, lostthing_id);
        g_in_safe_access = 0;
        if (ret >= 0) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_add_lostthing: added lostthing %d to %d instance(s)", lostthing_id, count);
    return count;
}

// ========== 添加卡牌到卡组 ==========
// cardsLibraryAll(0x90): List<CardInfoInDeck> — 卡牌库全列表（非战斗显示）
//   CardInfoInDeck: Il2CppObject header(16) + id(+0x10,int) + idx(+0x14,int)
// cardsBattle(0x100): List<Int32> — 战斗用卡组
//
// 策略: 同时向两个列表添加卡牌
//   cardsBattle: 直接 add_item_to_int_list (int list)
//   cardsLibraryAll: 构造 CardInfoInDeck 对象, 插入 List<ref> 的 backing array

// 向 List<Ref> (List<CardInfoInDeck>) 添加一个引用类型元素
// List<T> where T=class: _items 是 Il2CppArray of pointers
// SZArray<ref>: klass(8)+monitor(8)+bounds(8,=0)+max_length(8)+elements[](ptr,8 each)
static int add_card_to_ref_list(uintptr_t list_ptr, int card_id) {
    if (list_ptr < 0x10000) return -1;
    
    uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
    int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
    
    if (items < 0x10000 || size < 0 || size > 5000) {
        LOGW("  add_card_ref: invalid list (items=%p, size=%d)", (void*)items, size);
        return -1;
    }
    
    // 探测 SZArray 布局
    uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
    uintptr_t max_length;
    uintptr_t *elem_base;
    int compact = 0;
    
    if (probe == 0) {
        max_length = *(volatile uintptr_t *)(items + 0x18);
        elem_base = (uintptr_t *)(items + 0x20);
    } else if (probe > 0 && probe <= 200000) {
        max_length = probe;
        elem_base = (uintptr_t *)(items + 0x18);
        compact = 1;
    } else {
        max_length = *(volatile uintptr_t *)(items + 0x18);
        elem_base = (uintptr_t *)(items + 0x20);
    }
    
    LOGI("  add_card_ref: card=%d, size=%d, cap=%d", card_id, size, (int)max_length);
    
    // 注意: 不做去重检查, 游戏允许套牌中有多张相同卡牌
    
    // 扩容 (分配新 pointer array)
    if (max_length == 0 || (uintptr_t)size >= max_length) {
        int new_cap = (int)(max_length == 0 ? 32 : max_length * 2);
        if (new_cap < size + 4) new_cap = size + 4;
        if (new_cap > 5000) new_cap = 5000;
        
        // 分配新 SZArray<ref>: header + new_cap * 8(ptr)
        size_t hdr_sz = compact ? 0x18 : 0x20;
        size_t total = hdr_sz + (size_t)new_cap * 8;
        size_t page_sz = 4096;
        size_t alloc_sz = (total + page_sz - 1) & ~(page_sz - 1);
        void *mem = mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) return -1;
        memset(mem, 0, alloc_sz);
        uintptr_t new_arr = (uintptr_t)mem;
        
        // 复制头部 (匹配原数组布局)
        *(volatile uintptr_t *)(new_arr + 0x00) = *(volatile uintptr_t *)(items + 0x00);
        *(volatile uintptr_t *)(new_arr + 0x08) = *(volatile uintptr_t *)(items + 0x08);
        if (compact) {
            *(volatile uintptr_t *)(new_arr + 0x10) = (uintptr_t)new_cap;
        } else {
            *(volatile uintptr_t *)(new_arr + 0x10) = 0; // bounds=NULL
            *(volatile uintptr_t *)(new_arr + 0x18) = (uintptr_t)new_cap;
        }
        
        uintptr_t *new_elem = (uintptr_t *)(new_arr + hdr_sz);
        for (int i = 0; i < size; i++) {
            new_elem[i] = elem_base[i];
        }
        
        *(volatile uintptr_t *)(list_ptr + 0x10) = new_arr;
        elem_base = new_elem;
        max_length = (uintptr_t)new_cap;
        LOGI("  Expanded ref array: new cap=%d", new_cap);
    }
    
    // 分配 CardInfoInDeck 对象
    // Il2CppObject: klass(8) + monitor(8) + id(4) + idx(4) = 24 bytes
    // 从第一个元素借 klass 指针
    uintptr_t card_klass = 0;
    for (int i = 0; i < size; i++) {
        if (elem_base[i] > 0x10000) {
            card_klass = *(volatile uintptr_t *)(elem_base[i]);
            break;
        }
    }
    if (card_klass == 0) {
        // 没有现有元素可以借 klass, 尝试用 il2cpp_class_from_name
        card_klass = (uintptr_t)fn_class_from_name(g_csharp_image, "", "CardInfoInDeck");
        LOGI("  CardInfoInDeck klass from API: %p", (void*)card_klass);
    }
    
    // mmap 分配一个 CardInfoInDeck 对象 (24 bytes, 页对齐)
    void *obj_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (obj_mem == MAP_FAILED) return -1;
    memset(obj_mem, 0, 4096);
    uintptr_t card_obj = (uintptr_t)obj_mem;
    *(volatile uintptr_t *)(card_obj + 0x00) = card_klass; // klass
    *(volatile uintptr_t *)(card_obj + 0x08) = 0;          // monitor
    *(volatile int32_t *)(card_obj + 0x10) = card_id;      // id
    *(volatile int32_t *)(card_obj + 0x14) = size;         // idx (= 在列表中的索引)
    
    // 插入到 List
    elem_base[size] = card_obj;
    *(int32_t *)(list_ptr + 0x18) = size + 1;
    LOGI("  Added CardInfoInDeck(id=%d, idx=%d) @ %p to library (size: %d -> %d)",
         card_id, size, obj_mem, size, size + 1);
    return 1;
}

static int do_add_card(int card_id) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        
        int ok = 0;
        
        // 1. 向 cardsLibraryAll (List<CardInfoInDeck>) 添加（卡牌库，非战斗显示）
        uintptr_t lib_cards = *(volatile uintptr_t *)(obj_addr + 0x90);
        if (lib_cards > 0x10000) {
            int ret = add_card_to_ref_list(lib_cards, card_id);
            if (ret >= 0) ok = 1;
        }
        
        // 2. 向 cardsBattle (List<Int32>) 添加（战斗用卡组）
        uintptr_t battle_cards = *(volatile uintptr_t *)(obj_addr + 0x100);
        if (battle_cards > 0x10000) {
            add_item_to_int_list(battle_cards, card_id);
        }
        
        g_in_safe_access = 0;
        if (ok) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_add_card: added card %d to %d instance(s)", card_id, count);
    return count;
}

// ========== 修改装备槽数量 ==========
// equipmentSlot 是 List<Int32>, size = 装备槽数量
// 空槽 value=0, 有装备 value=itemID
// 扩容: 在数组容量允许的范围内增加 size, 新槽填 0
// 缩容: 减少 size (不释放数组空间)
static int do_modify_equip_slots(int slot_count) {
    if (init_il2cpp_context() != 0) return -1;
    if (slot_count < 0 || slot_count > 50) {
        LOGW("do_modify_equip_slots: invalid slot_count %d", slot_count);
        return -1;
    }
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;

    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t equip_list = *(volatile uintptr_t *)(obj_addr + OFF_EQUIPSLOT);
        if (equip_list < 0x10000) { g_in_safe_access = 0; continue; }

        uintptr_t items = *(volatile uintptr_t *)(equip_list + 0x10);
        int32_t cur_size = *(volatile int32_t *)(equip_list + 0x18);
        g_in_safe_access = 0;

        if (items < 0x10000 || cur_size < 0) continue;

        // 探测 SZArray 布局获取 max_length 和 elem_base
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
        uintptr_t max_length;
        int32_t *elem_base;
        int compact = 0;
        if (probe == 0) {
            max_length = *(volatile uintptr_t *)(items + 0x18);
            elem_base = (int32_t *)(items + 0x20);
        } else if (probe > 0 && probe <= 200000) {
            max_length = probe;
            elem_base = (int32_t *)(items + 0x18);
            compact = 1;
        } else {
            uint32_t lo32 = (uint32_t)(probe & 0xFFFFFFFF);
            if (lo32 > 0 && lo32 <= 200000) {
                max_length = lo32;
                elem_base = (int32_t *)(items + 0x18);
                compact = 1;
            } else {
                max_length = *(volatile uintptr_t *)(items + 0x18);
                elem_base = (int32_t *)(items + 0x20);
            }
        }
        g_in_safe_access = 0;

        LOGI("  equip_slots: cur_size=%d, cap=%d, target=%d", cur_size, (int)max_length, slot_count);

        // 如果目标 > 当前容量，需要扩容
        if ((uintptr_t)slot_count > max_length) {
            int new_cap = slot_count + 4;
            LOGI("  equip_slots: expanding cap %d -> %d", (int)max_length, new_cap);
            
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            uintptr_t new_arr = alloc_int32_szarray(items, new_cap, compact);
            g_in_safe_access = 0;
            
            if (!new_arr) continue;
            
            // 拷贝旧元素 (偏移取决于布局)
            int32_t *new_elem = (int32_t *)(new_arr + (compact ? 0x18 : 0x20));
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            for (int s = 0; s < cur_size; s++) {
                new_elem[s] = elem_base[s];
            }
            // 替换 _items
            *(volatile uintptr_t *)(equip_list + 0x10) = new_arr;
            g_in_safe_access = 0;
            
            items = new_arr;
            elem_base = new_elem;
            max_length = (uintptr_t)new_cap;
        }

        int new_size = slot_count;
        if ((uintptr_t)new_size > max_length) {
            new_size = (int)max_length;
        }

        // 新增的槽位填 0 (空槽)
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        for (int s = cur_size; s < new_size; s++) {
            elem_base[s] = 0;
        }
        *(int32_t *)(equip_list + 0x18) = new_size;
        g_in_safe_access = 0;

        LOGI("  equip_slots: changed %d -> %d", cur_size, new_size);
        count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_equip_slots: set to %d on %d instance(s)", slot_count, count);
    return count;
}

// ========== 读取当前物品列表 (返回 JSON 数组) ==========
// type: 1=卡牌(cardsBattle 0x100), 2=祝福(lostThingList 0xb8), 3=装备(equipmentSlot 0x98)
static char* do_get_current_items(int type) {
    if (init_il2cpp_context() != 0) return strdup("[]");
    int n = ensure_roleinfo_cached();
    if (n == 0) return strdup("[]");
    
    // 从第一个 RoleInfo 实例读取
    uintptr_t obj_addr = g_cached_roleinfo[0];
    
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        return strdup("[]");
    }
    
    // ===== 卡牌: 从 cardsLibraryAll (List<CardInfoInDeck>) 读取 =====
    if (type == 1) {
        uintptr_t list_ptr = *(volatile uintptr_t *)(obj_addr + 0x90);
        if (list_ptr < 0x10000) { g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]"); }
        
        uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
        int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
        
        if (items < 0x10000 || size <= 0 || size > 5000) {
            g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]");
        }
        
        uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
        uintptr_t *elem_base;
        if (probe == 0) elem_base = (uintptr_t *)(items + 0x20);
        else if (probe > 0 && probe <= 200000) elem_base = (uintptr_t *)(items + 0x18);
        else elem_base = (uintptr_t *)(items + 0x20);
        
        size_t buf_size = (size_t)size * 12 + 8;
        char *buf = (char *)malloc(buf_size);
        if (!buf) { g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]"); }
        
        int pos = 0;
        buf[pos++] = '[';
        for (int i = 0; i < size; i++) {
            uintptr_t obj = elem_base[i];
            if (obj < 0x10000) continue;
            int32_t card_id = *(volatile int32_t *)(obj + 0x10);
            if (card_id <= 0) continue;
            if (pos > 1) buf[pos++] = ',';
            pos += snprintf(buf + pos, buf_size - pos, "%d", card_id);
        }
        buf[pos++] = ']';
        buf[pos] = '\0';
        
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        LOGI("do_get_current_items(type=1/cardsLibraryAll): size=%d, json=%s", size, buf);
        return buf;
    }
    
    // ===== 祝福/装备: List<Int32> =====
    uintptr_t list_offset;
    switch (type) {
        case 2: list_offset = OFF_LOSTTHING; break;
        case 3: list_offset = OFF_EQUIPSLOT; break;
        default: g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]");
    }
    
    uintptr_t list_ptr = *(volatile uintptr_t *)(obj_addr + list_offset);
    if (list_ptr < 0x10000) { g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]"); }
    
    uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
    int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
    
    if (items < 0x10000 || size <= 0 || size > 2000) {
        g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]");
    }
    
    // 探测 SZArray 布局
    uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
    int32_t *elem_base;
    if (probe == 0) {
        elem_base = (int32_t *)(items + 0x20);
    } else if (probe > 0 && probe <= 200000) {
        elem_base = (int32_t *)(items + 0x18);
    } else {
        elem_base = (int32_t *)(items + 0x20);
    }
    
    // 构建 JSON 数组
    size_t buf_size = (size_t)size * 12 + 8;
    char *buf = (char *)malloc(buf_size);
    if (!buf) { g_in_safe_access = 0; uninstall_sigsegv_handler(); return strdup("[]"); }
    
    int pos = 0;
    buf[pos++] = '[';
    for (int i = 0; i < size; i++) {
        int32_t val = elem_base[i];
        if (val == 0 && type == 3) continue; // 跳过装备空槽
        if (i > 0 && pos > 1) buf[pos++] = ',';
        pos += snprintf(buf + pos, buf_size - pos, "%d", val);
    }
    buf[pos++] = ']';
    buf[pos] = '\0';
    
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    LOGI("do_get_current_items(type=%d): size=%d, json=%s", type, size, buf);
    return buf;
}

// ========== 从 List<Int32> 中移除指定 ID ==========
// 找到 item_id, 将后续元素左移, size-1
// 返回: 1=已移除, 0=未找到, -1=错误
static int remove_item_from_int_list(uintptr_t list_ptr, int item_id) {
    if (list_ptr < 0x10000) return -1;
    
    uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
    int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
    
    if (items < 0x10000 || size <= 0 || size > 2000) return -1;
    
    uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
    int32_t *elem_base;
    if (probe == 0) {
        elem_base = (int32_t *)(items + 0x20);
    } else if (probe > 0 && probe <= 200000) {
        elem_base = (int32_t *)(items + 0x18);
    } else {
        elem_base = (int32_t *)(items + 0x20);
    }
    
    // 查找并移除
    for (int i = 0; i < size; i++) {
        if (elem_base[i] == item_id) {
            // 左移后续元素
            for (int j = i; j < size - 1; j++) {
                elem_base[j] = elem_base[j + 1];
            }
            elem_base[size - 1] = 0;
            *(int32_t *)(list_ptr + 0x18) = size - 1;
            LOGI("  Removed item %d from list (size: %d -> %d)", item_id, size, size - 1);
            return 1;
        }
    }
    return 0; // 未找到
}

// ========== 从 List<CardInfoInDeck> 中按 id 移除 ==========
static int remove_card_from_ref_list(uintptr_t list_ptr, int card_id) {
    if (list_ptr < 0x10000) return -1;
    
    uintptr_t items = *(volatile uintptr_t *)(list_ptr + 0x10);
    int32_t size = *(volatile int32_t *)(list_ptr + 0x18);
    
    if (items < 0x10000 || size <= 0 || size > 5000) return -1;
    
    uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
    uintptr_t *elem_base;
    if (probe == 0) {
        elem_base = (uintptr_t *)(items + 0x20);
    } else if (probe > 0 && probe <= 200000) {
        elem_base = (uintptr_t *)(items + 0x18);
    } else {
        elem_base = (uintptr_t *)(items + 0x20);
    }
    
    for (int i = 0; i < size; i++) {
        uintptr_t obj = elem_base[i];
        if (obj < 0x10000) continue;
        int32_t eid = *(volatile int32_t *)(obj + 0x10);
        if (eid == card_id) {
            for (int j = i; j < size - 1; j++) {
                elem_base[j] = elem_base[j + 1];
            }
            elem_base[size - 1] = 0;
            *(int32_t *)(list_ptr + 0x18) = size - 1;
            LOGI("  Removed CardInfoInDeck(id=%d) from ref list (size: %d -> %d)", card_id, size, size - 1);
            return 1;
        }
    }
    return 0;
}

// ========== 删除卡牌 ==========
static int do_remove_card(int card_id) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        
        int ok = 0;
        
        // 1. 从 cardsLibraryAll (List<CardInfoInDeck>) 移除
        uintptr_t lib_cards = *(volatile uintptr_t *)(obj_addr + 0x90);
        if (lib_cards > 0x10000) {
            if (remove_card_from_ref_list(lib_cards, card_id) > 0) ok = 1;
        }
        
        // 2. 从 cardsBattle (List<Int32>) 移除
        uintptr_t battle_cards = *(volatile uintptr_t *)(obj_addr + 0x100);
        if (battle_cards > 0x10000) {
            remove_item_from_int_list(battle_cards, card_id);
        }
        
        g_in_safe_access = 0;
        if (ok) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_remove_card: removed card %d from %d instance(s)", card_id, count);
    return count;
}

// ========== 删除祝福/遗物 ==========
static int do_remove_lostthing(int lostthing_id) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t lt_list = *(volatile uintptr_t *)(obj_addr + OFF_LOSTTHING);
        int ret = remove_item_from_int_list(lt_list, lostthing_id);
        g_in_safe_access = 0;
        if (ret > 0) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_remove_lostthing: removed %d from %d instance(s)", lostthing_id, count);
    return count;
}

// ========== 设置卡牌数量 ==========
// 将卡牌 card_id 在套牌中的数量调整为 target_count
// 通过统计当前数量, 然后 add/remove 差值来实现
static char* do_set_card_count(int card_id, int target_count) {
    if (target_count < 0 || target_count > 99) return strdup("\u274C 数量无效(0-99)");
    if (init_il2cpp_context() != 0) return strdup("\u274C il2cpp未初始化");
    int n = ensure_roleinfo_cached();
    if (n == 0) return strdup("\u274C 无RoleInfo");
    
    // 统计 cardsLibraryAll 中 card_id 的当前数量
    uintptr_t obj_addr = g_cached_roleinfo[0];
    
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        return strdup("\u274C 内存访问错误");
    }
    
    int current_count = 0;
    uintptr_t lib_list = *(volatile uintptr_t *)(obj_addr + 0x90);
    if (lib_list > 0x10000) {
        uintptr_t items = *(volatile uintptr_t *)(lib_list + 0x10);
        int32_t size = *(volatile int32_t *)(lib_list + 0x18);
        if (items > 0x10000 && size > 0 && size <= 5000) {
            uintptr_t probe = *(volatile uintptr_t *)(items + 0x10);
            uintptr_t *elem_base;
            if (probe == 0) elem_base = (uintptr_t *)(items + 0x20);
            else if (probe > 0 && probe <= 200000) elem_base = (uintptr_t *)(items + 0x18);
            else elem_base = (uintptr_t *)(items + 0x20);
            for (int i = 0; i < size; i++) {
                uintptr_t obj = elem_base[i];
                if (obj > 0x10000 && *(volatile int32_t *)(obj + 0x10) == card_id)
                    current_count++;
            }
        }
    }
    
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    
    LOGI("do_set_card_count: card=%d, current=%d, target=%d", card_id, current_count, target_count);
    
    char buf[128];
    if (target_count == current_count) {
        snprintf(buf, sizeof(buf), "\u2705 卡牌%d 数量已是 %d", card_id, current_count);
        return strdup(buf);
    }
    
    if (target_count > current_count) {
        int to_add = target_count - current_count;
        for (int i = 0; i < to_add; i++) do_add_card(card_id);
        snprintf(buf, sizeof(buf), "\u2705 卡牌%d: %d \u2192 %d (+%d)", card_id, current_count, target_count, to_add);
    } else {
        int to_remove = current_count - target_count;
        for (int i = 0; i < to_remove; i++) do_remove_card(card_id);
        snprintf(buf, sizeof(buf), "\u2705 卡牌%d: %d \u2192 %d (-%d)", card_id, current_count, target_count, to_remove);
    }
    return strdup(buf);
}

// ========== IL2CPP 字符串读取 (UTF-16LE → UTF-8) ==========
// Il2CppString: klass(8) + monitor(8) + length(4) + chars[](UTF-16LE)
static int utf16_to_utf8(const uint16_t *src, int src_len, char *dst, int dst_max) {
    int j = 0;
    for (int i = 0; i < src_len && j < dst_max - 4; i++) {
        uint16_t c = src[i];
        if (c < 0x80) {
            dst[j++] = (char)c;
        } else if (c < 0x800) {
            dst[j++] = (char)(0xC0 | (c >> 6));
            dst[j++] = (char)(0x80 | (c & 0x3F));
        } else {
            if (c >= 0xD800 && c <= 0xDBFF && i + 1 < src_len) {
                uint16_t c2 = src[i + 1];
                if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                    uint32_t cp = 0x10000 + ((uint32_t)(c - 0xD800) << 10) + (c2 - 0xDC00);
                    dst[j++] = (char)(0xF0 | (cp >> 18));
                    dst[j++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                    dst[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    dst[j++] = (char)(0x80 | (cp & 0x3F));
                    i++;
                    continue;
                }
            }
            dst[j++] = (char)(0xE0 | (c >> 12));
            dst[j++] = (char)(0x80 | ((c >> 6) & 0x3F));
            dst[j++] = (char)(0x80 | (c & 0x3F));
        }
    }
    dst[j] = '\0';
    return j;
}

// 安全读取 il2cpp String 到 UTF-8 (带 SIGSEGV 保护)
static int safe_read_il2cpp_string(uintptr_t str_ptr, char *buf, int buf_size) {
    if (str_ptr < 0x10000 || buf_size < 4) { buf[0] = '\0'; return 0; }
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; buf[0] = '\0'; return 0; }
    int32_t len = *(volatile int32_t *)(str_ptr + 0x10);
    if (len <= 0 || len > 200) { g_in_safe_access = 0; buf[0] = '\0'; return 0; }
    uint16_t *chars = (uint16_t *)(str_ptr + 0x14);
    int result = utf16_to_utf8(chars, len, buf, buf_size);
    g_in_safe_access = 0;
    return result;
}

// ========== 配置类实例缓存 ==========
// 避免每次浏览都做全堆扫描 (数秒)
typedef struct {
    uintptr_t klass;
    uintptr_t addr;
} ConfigCache;
static ConfigCache g_config_cache[4] = {0}; // index by item_type: 1=card, 2=lostthing, 3=equip

static uintptr_t get_cached_config(int item_type, uintptr_t klass_val) {
    if (item_type < 1 || item_type > 3 || klass_val == 0) return 0;
    ConfigCache *cc = &g_config_cache[item_type];
    if (cc->klass != klass_val || cc->addr == 0) return 0;
    // 验证缓存地址仍然有效
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0;
        uninstall_sigsegv_handler();
        cc->addr = 0;
        LOGW("[cache] item_type=%d cached addr invalid, cleared", item_type);
        return 0;
    }
    uintptr_t k = *(volatile uintptr_t *)cc->addr;
    g_in_safe_access = 0;
    uninstall_sigsegv_handler();
    if (k != klass_val) {
        LOGW("[cache] item_type=%d klass mismatch, cleared", item_type);
        cc->addr = 0;
        return 0;
    }
    LOGI("[cache] Hit! item_type=%d @ %p", item_type, (void*)cc->addr);
    return cc->addr;
}

static void set_config_cache(int item_type, uintptr_t klass_val, uintptr_t addr) {
    if (item_type < 1 || item_type > 3) return;
    g_config_cache[item_type].klass = klass_val;
    g_config_cache[item_type].addr = addr;
    LOGI("[cache] Stored item_type=%d @ %p", item_type, (void*)addr);
}

// ========== 扫描堆查找某个类的单一实例 ==========
// 用于找到 CardsConfig / LostThingConfig 等单例配置类
// 改进: 找到所有候选实例, 选择 dict count 最大的那个 (避免假阳性)
static uintptr_t find_single_class_instance(uintptr_t klass_val) {
    if (klass_val == 0) return 0;
    parse_maps();
    install_sigsegv_handler();
    uintptr_t best_addr = 0;
    int32_t best_count = 0;

    for (int r = 0; r < g_region_count; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        if (region->executable) continue;
        size_t size = region->end - region->start;
        if (size < 0x100 || size > MAX_SCAN_SIZE) continue;
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;

        uint8_t *base = (uint8_t *)region->start;
        for (size_t off = 0; off <= size - 0x40; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; break; }
            uintptr_t val = *(volatile uintptr_t *)(base + off);
            if (val != klass_val) { g_in_safe_access = 0; continue; }
            // 验证: +0x10 (configs dict) 应该是有效指针
            uintptr_t dict_ptr = *(volatile uintptr_t *)(base + off + 0x10);
            if (dict_ptr < 0x10000) { g_in_safe_access = 0; continue; }
            // 进一步验证: dict 的 count 字段应合理
            int32_t count = *(volatile int32_t *)(dict_ptr + 0x20);
            if (count > 0 && count < 100000 && count > best_count) {
                best_count = count;
                best_addr = (uintptr_t)(base + off);
                LOGI("[scan] Candidate @ %p, dict count=%d", (void*)best_addr, count);
            }
            g_in_safe_access = 0;
        }
    }
    uninstall_sigsegv_handler();
    if (best_addr) {
        LOGI("[scan] Selected best instance @ %p (count=%d)", (void*)best_addr, best_count);
    }
    return best_addr;
}

// JSON 转义辅助
static void json_escape_append(char **dst, int *remaining, const char *src) {
    char *p = *dst;
    int rem = *remaining;
    while (*src && rem > 6) {
        char c = *src++;
        if (c == '"' || c == '\\') { *p++ = '\\'; *p++ = c; rem -= 2; }
        else if ((unsigned char)c >= 0x20) { *p++ = c; rem--; }
    }
    *dst = p;
    *remaining = rem;
}

// ========== 枚举配置项 (运行时从内存读取) ==========
// item_type: 1=卡牌(CardsConfig), 2=祝福/遗物(LostThingConfig), 3=装备(MinionEquipConfig)
// 返回 JSON 数组: [{"id":1001,"n":"金剑"},...]
// 调用者负责 free 返回的字符串
//
// Dictionary<Int32, T> 内存布局 (ARM64, Il2CppObject header):
//   +0x00 klass pointer
//   +0x08 monitor
//   +0x10 int[]   _buckets
//   +0x18 Entry[] _entries
//   +0x20 int     _count
//   +0x24 int     _version
//
// Il2CppArray (SZArray) 头部布局:
//   +0x00 klass (8)
//   +0x08 monitor (8)
//   +0x10 bounds (8, SZArray = NULL)
//   +0x18 max_length (4/8)
//   元素从 +0x20 开始 (含 bounds 时) 或 +0x18 (无 bounds)
//
// Entry<Int32, T> 布局 (24 bytes, T=reference type):
//   +0  int hashCode (-1 = empty)
//   +4  int next
//   +8  int key (= item id)
//   +12 padding (4)
//   +16 T value (pointer, 8)
//
// CardInfo fields: [0x10] id, [0x28] String name
// MinionEquipCfgData fields: [0x14] id, [0x18] String name (parent: TierBase)
// LostThing: 自动检测 name 字段偏移
static char* do_prescan(void); // 前向声明
static char* do_enum_items(int item_type) {
    if (init_il2cpp_context() != 0) return NULL;

    // 自动预加载: 确保 config 缓存已填充
    if (g_cached_count == 0 || g_config_cache[item_type].addr == 0) {
        LOGI("[enum] Auto prescan for type=%d...", item_type);
        char *ps = do_prescan();
        if (ps) free(ps);
    }

    const char *class_name;
    int known_name_off;
    switch (item_type) {
        case 1: class_name = "CardsConfig"; known_name_off = 0x28; break;
        case 2: class_name = "LostThingConfig"; known_name_off = -1; break;
        case 3: class_name = "MinionEquipConfig"; known_name_off = 0x18; break;
        default: LOGE("[enum] Unknown item_type %d", item_type); return NULL;
    }

    LOGI("[enum] Looking for %s...", class_name);
    Il2CppClass klass = fn_class_from_name(g_csharp_image, "", class_name);
    if (!klass) { LOGE("[enum] Class %s not found", class_name); return NULL; }

    // 先查缓存, 缓存未命中再全堆扫描
    uintptr_t instance = get_cached_config(item_type, (uintptr_t)klass);
    if (!instance) {
        LOGI("[enum] %s klass=%p, scanning heap...", class_name, klass);
        instance = find_single_class_instance((uintptr_t)klass);
        if (instance) set_config_cache(item_type, (uintptr_t)klass, instance);
    }
    if (!instance) { LOGE("[enum] No %s instance in heap", class_name); return NULL; }
    LOGI("[enum] Instance @ 0x%" PRIxPTR, instance);

    // 读取 configs Dictionary<Int32, T>
    install_sigsegv_handler();
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0; uninstall_sigsegv_handler();
        LOGE("[enum] SIGSEGV reading dict header"); return NULL;
    }
    uintptr_t dict = *(volatile uintptr_t *)(instance + 0x10);
    if (dict < 0x10000) { g_in_safe_access = 0; uninstall_sigsegv_handler(); return NULL; }
    uintptr_t entries_arr = *(volatile uintptr_t *)(dict + 0x18);
    int32_t dict_count = *(volatile int32_t *)(dict + 0x20);
    g_in_safe_access = 0;
    LOGI("[enum] Dict count=%d entries_arr=0x%" PRIxPTR, dict_count, entries_arr);

    if (entries_arr < 0x10000 || dict_count <= 0 || dict_count > 100000) {
        LOGE("[enum] Invalid dict: entries_arr=%p count=%d", (void*)entries_arr, dict_count);
        uninstall_sigsegv_handler(); return NULL;
    }

    // 探测 IL2CppArray 头部布局, 确定元素起始位置
    // SZArray 可能有 bounds 字段(=NULL) 也可能没有
    g_in_safe_access = 1;
    if (sigsetjmp(g_jmpbuf, 1) != 0) {
        g_in_safe_access = 0; uninstall_sigsegv_handler();
        LOGE("[enum] SIGSEGV probing array header"); return NULL;
    }
    uintptr_t probe_10 = *(volatile uintptr_t *)(entries_arr + 0x10);
    g_in_safe_access = 0;

    uintptr_t elem_base;
    if (probe_10 == 0) {
        // bounds = NULL (标准 SZArray), max_length at +0x18, 元素从 +0x20
        elem_base = entries_arr + 0x20;
        LOGI("[enum] Array: bounds=NULL, elem_base=+0x20");
    } else if (probe_10 > 0 && probe_10 <= 200000) {
        // 无 bounds 字段, +0x10 直接是 max_length (8字节), 元素从 +0x18
        elem_base = entries_arr + 0x18;
        LOGI("[enum] Array: no bounds, maxlen=%d, elem_base=+0x18", (int)probe_10);
    } else {
        // probe_10 很大: 可能是 int32 max_length + 首条目数据合并读取
        // 检查低 32 位是否是合理的 max_length
        uint32_t lo32 = (uint32_t)(probe_10 & 0xFFFFFFFF);
        if (lo32 > 0 && lo32 <= 200000) {
            // int32 max_length + 4字节 padding/data, Entry[] 需要 8 字节对齐
            elem_base = entries_arr + 0x18;
            LOGI("[enum] Array: int32 maxlen=%u (+entry data), elem_base=+0x18", lo32);
        } else {
            // 真正的 bounds 指针, max_length at +0x18, 元素从 +0x20
            elem_base = entries_arr + 0x20;
            LOGI("[enum] Array: bounds=%p, elem_base=+0x20", (void*)probe_10);
        }
    }

    // 使用 dict_count 作为迭代上限 (Dictionary._count = 已用 entry 的高水位线)
    int iter_limit = dict_count;

    // 自动检测 name 字段偏移 (如果未知)
    int name_off = known_name_off;
    if (name_off < 0) {
        int candidates[] = {0x18, 0x28, 0x20, 0x30, 0x38, 0x40, -1};
        for (int i = 0; i < iter_limit && name_off < 0; i++) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            uintptr_t entry = elem_base + (uintptr_t)i * 24;
            int32_t hc = *(volatile int32_t *)(entry);
            if (hc < 0) { g_in_safe_access = 0; continue; }
            uintptr_t val = *(volatile uintptr_t *)(entry + 16);
            g_in_safe_access = 0;
            if (val < 0x10000) continue;
            for (int k = 0; candidates[k] >= 0; k++) {
                g_in_safe_access = 1;
                if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
                uintptr_t sp = *(volatile uintptr_t *)(val + candidates[k]);
                g_in_safe_access = 0;
                char tb[64];
                if (safe_read_il2cpp_string(sp, tb, sizeof(tb)) > 0) {
                    name_off = candidates[k];
                    LOGI("[enum] Auto-detected name offset=0x%x: \"%s\"", name_off, tb);
                    break;
                }
            }
        }
        if (name_off < 0) { name_off = 0x18; LOGW("[enum] Fallback name offset=0x18"); }
    }

    // 构建 JSON
    int json_cap = dict_count * 100 + 32;
    char *json = (char *)malloc(json_cap);
    if (!json) { uninstall_sigsegv_handler(); return NULL; }

    char *p = json;
    int remaining = json_cap - 2;
    *p++ = '['; remaining--;
    int first = 1, added = 0;

    for (int i = 0; i < iter_limit && remaining > 120; i++) {
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t entry = elem_base + (uintptr_t)i * 24;
        int32_t hc = *(volatile int32_t *)(entry);
        if (hc < 0) { g_in_safe_access = 0; continue; }
        int32_t key = *(volatile int32_t *)(entry + 8);
        uintptr_t value = *(volatile uintptr_t *)(entry + 16);
        g_in_safe_access = 0;
        if (value < 0x10000) continue;

        // 读取 name String
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        uintptr_t name_str = *(volatile uintptr_t *)(value + name_off);
        g_in_safe_access = 0;

        char name_buf[256] = {0};
        safe_read_il2cpp_string(name_str, name_buf, sizeof(name_buf));

        if (!first) { *p++ = ','; remaining--; }
        first = 0;
        int n = snprintf(p, remaining, "{\"id\":%d,\"n\":\"", key);
        p += n; remaining -= n;
        json_escape_append(&p, &remaining, name_buf[0] ? name_buf : "???");
        n = snprintf(p, remaining, "\"}");
        p += n; remaining -= n;
        added++;
    }

    // 如果首次未找到任何条目, 尝试另一个 elem_base 偏移
    if (added == 0 && dict_count > 5) {
        uintptr_t alt_base = (elem_base == entries_arr + 0x20)
                              ? entries_arr + 0x18
                              : entries_arr + 0x20;
        LOGW("[enum] 0 items with elem_base=%p, retrying with alt=%p",
             (void*)elem_base, (void*)alt_base);

        p = json; remaining = json_cap - 2;
        *p++ = '['; remaining--;
        first = 1;

        for (int i = 0; i < iter_limit && remaining > 120; i++) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            uintptr_t entry = alt_base + (uintptr_t)i * 24;
            int32_t hc = *(volatile int32_t *)(entry);
            if (hc < 0) { g_in_safe_access = 0; continue; }
            int32_t key = *(volatile int32_t *)(entry + 8);
            uintptr_t value = *(volatile uintptr_t *)(entry + 16);
            g_in_safe_access = 0;
            if (value < 0x10000) continue;

            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            uintptr_t name_str = *(volatile uintptr_t *)(value + name_off);
            g_in_safe_access = 0;

            char name_buf[256] = {0};
            safe_read_il2cpp_string(name_str, name_buf, sizeof(name_buf));

            if (!first) { *p++ = ','; remaining--; }
            first = 0;
            int n = snprintf(p, remaining, "{\"id\":%d,\"n\":\"", key);
            p += n; remaining -= n;
            json_escape_append(&p, &remaining, name_buf[0] ? name_buf : "???");
            n = snprintf(p, remaining, "\"}");
            p += n; remaining -= n;
            added++;
        }
    }

    *p++ = ']'; *p = '\0';

    uninstall_sigsegv_handler();
    LOGI("[enum] Enumerated %d items for type %d (json len=%d)", added, item_type, (int)(p - json));
    return json;
}

// ========== 一键修改所有属性 ==========
static int do_modify_all_stats(int gold, int max_hp, int mp, int action, int handcards) {
    if (init_il2cpp_context() != 0) return -1;
    int n = ensure_roleinfo_cached();
    if (n == 0) return 0;
    
    int count = 0;
    install_sigsegv_handler();
    for (int i = 0; i < g_cached_count; i++) {
        uintptr_t obj_addr = g_cached_roleinfo[i];
        g_in_safe_access = 1;
        if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
        
        if (gold > 0) {
            int32_t old = *(int32_t *)(obj_addr + OFF_CURGOLD);
            *(int32_t *)(obj_addr + OFF_CURGOLD) = gold;
            LOGI("  => Gold: %d -> %d", old, gold);
        }
        if (max_hp > 0) {
            int32_t old_max = *(int32_t *)(obj_addr + OFF_MAXHP);
            *(int32_t *)(obj_addr + OFF_MAXHP) = max_hp;
            *(int32_t *)(obj_addr + OFF_CURHP) = max_hp;
            LOGI("  => HP: %d -> %d/%d", old_max, max_hp, max_hp);
        }
        if (mp >= 0) {
            int32_t old = *(int32_t *)(obj_addr + OFF_CURMP);
            *(int32_t *)(obj_addr + OFF_CURMP) = mp;
            LOGI("  => MP: %d -> %d", old, mp);
        }
        if (action > 0) {
            int32_t old = *(int32_t *)(obj_addr + OFF_CURACTION);
            *(int32_t *)(obj_addr + OFF_CURACTION) = action;
            LOGI("  => Action: %d -> %d", old, action);
        }
        if (handcards > 0) {
            int32_t old = *(int32_t *)(obj_addr + OFF_HANDCARDS);
            *(int32_t *)(obj_addr + OFF_HANDCARDS) = handcards;
            LOGI("  => Handcards: %d -> %d", old, handcards);
        }
        g_in_safe_access = 0;
        count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_modify_all_stats: modified %d instance(s)", count);
    return count;
}

// ========== 同时修改金币和技能（兼容旧的一次性模式）==========
static int modify_gold(int target_gold) {
    if (init_il2cpp_context() != 0) return -1;
    // 一次性模式直接全量扫描
    scan_and_cache_roleinfo();
    if (g_cached_count == 0) return 0;
    
    int gold_count = do_modify_gold(target_gold);
    do_reset_skill_cd();
    return gold_count;
}

// ========== JNI native 方法实现（供 Java 悬浮菜单回调）==========
static jstring JNICALL jni_modify_gold(JNIEnv *env, jclass clazz, jint amount) {
    LOGI("[JNI] nativeModifyGold(%d)", (int)amount);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0) {
        LOGW("[JNI] nativeModifyGold busy, skipping");
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中，请稍候...");
    }
    int count = do_modify_gold((int)amount);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 金币已修改为 %d (%d个实例)", (int)amount, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例(需在游戏对局中)");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

static jstring JNICALL jni_reset_skill_cd(JNIEnv *env, jclass clazz) {
    LOGI("[JNI] nativeResetSkillCD");
    if (pthread_mutex_trylock(&g_hack_mutex) != 0) {
        LOGW("[JNI] nativeResetSkillCD busy, skipping");
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中，请稍候...");
    }
    int count = do_reset_skill_cd();
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 已重置 %d 个技能CD", count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到需要重置的技能");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 修改血量 ==========
static jstring JNICALL jni_modify_hp(JNIEnv *env, jclass clazz, jint max_hp) {
    LOGI("[JNI] nativeModifyHp(%d)", (int)max_hp);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_hp((int)max_hp);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 血量: %d/%d (%d个实例)", (int)max_hp, (int)max_hp, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 修改法力值 ==========
static jstring JNICALL jni_modify_mp(JNIEnv *env, jclass clazz, jint mp) {
    LOGI("[JNI] nativeModifyMp(%d)", (int)mp);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_mp((int)mp);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 法力: %d (%d个实例)", (int)mp, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 修改行动值 ==========
static jstring JNICALL jni_modify_action(JNIEnv *env, jclass clazz, jint action) {
    LOGI("[JNI] nativeModifyAction(%d)", (int)action);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_action((int)action);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 行动值: %d (%d个实例)", (int)action, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 修改手牌上限 ==========
static jstring JNICALL jni_modify_handcards(JNIEnv *env, jclass clazz, jint handcards) {
    LOGI("[JNI] nativeModifyHandcards(%d)", (int)handcards);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_handcards((int)handcards);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 手牌上限: %d (%d个实例)", (int)handcards, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 添加装备 ==========
static jstring JNICALL jni_add_equipment(JNIEnv *env, jclass clazz, jint equip_id) {
    LOGI("[JNI] nativeAddEquipment(%d)", (int)equip_id);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_add_equipment((int)equip_id);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 装备 %d 已添加 (%d个实例)", (int)equip_id, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C 添加失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 添加祝福/遗物 ==========
static jstring JNICALL jni_add_lostthing(JNIEnv *env, jclass clazz, jint lt_id) {
    LOGI("[JNI] nativeAddLostThing(%d)", (int)lt_id);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_add_lostthing((int)lt_id);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 祝福 %d 已添加 (%d个实例)", (int)lt_id, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C 添加失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 添加卡牌 ==========
static jstring JNICALL jni_add_card(JNIEnv *env, jclass clazz, jint card_id) {
    LOGI("[JNI] nativeAddCard(%d)", (int)card_id);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_add_card((int)card_id);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 卡牌 %d 已添加 (%d个实例)", (int)card_id, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C 添加失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 一键修改所有属性 ==========
static jstring JNICALL jni_modify_all(JNIEnv *env, jclass clazz, jint gold, jint max_hp, jint mp, jint action, jint handcards) {
    LOGI("[JNI] nativeModifyAll(gold=%d, hp=%d, mp=%d, action=%d, hand=%d)",
         (int)gold, (int)max_hp, (int)mp, (int)action, (int)handcards);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_all_stats((int)gold, (int)max_hp, (int)mp, (int)action, (int)handcards);
    do_reset_skill_cd();
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[256];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 全部修改完成 (%d个实例)", count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C API 初始化失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 枚举配置项 (返回 JSON) ==========
static jstring JNICALL jni_enum_items(JNIEnv *env, jclass clazz, jint type) {
    LOGI("[JNI] nativeEnumItems(%d)", (int)type);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "[]");
    char *json = do_enum_items((int)type);
    pthread_mutex_unlock(&g_hack_mutex);
    if (!json) return (*env)->NewStringUTF(env, "[]");
    jstring result = (*env)->NewStringUTF(env, json);
    free(json);
    return result;
}

// ========== JNI: 修改装备槽数量 ==========
static jstring JNICALL jni_modify_equip_slots(JNIEnv *env, jclass clazz, jint slots) {
    LOGI("[JNI] nativeModifyEquipSlots(%d)", (int)slots);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    int count = do_modify_equip_slots((int)slots);
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[128];
    if (count > 0)
        snprintf(buf, sizeof(buf), "\u2705 装备槽: %d (%d个实例)", (int)slots, count);
    else if (count == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到实例");
    else
        snprintf(buf, sizeof(buf), "\u274C 修改失败");
    return (*env)->NewStringUTF(env, buf);
}

// ========== 多线程预扫描 ==========
#define NUM_SCAN_THREADS 4
#define PRESCAN_SLOTS 5

typedef struct {
    int region_start;           // g_regions 起始索引 (含)
    int region_end;             // g_regions 结束索引 (不含)
    uintptr_t target_klass[PRESCAN_SLOTS];
    // 每线程本地结果
    uintptr_t local_roleinfo[MAX_CACHED_ROLEINFO];
    int       local_ri_count;
    uintptr_t local_warinfo[MAX_CACHED_WARINFO];
    int       local_wi_count;
    uintptr_t local_cfg_addr[3];
    int32_t   local_cfg_count[3];
} PrescanWorkerArg;

static void* prescan_worker(void *arg) {
    PrescanWorkerArg *wa = (PrescanWorkerArg *)arg;
    wa->local_ri_count = 0;
    wa->local_wi_count = 0;
    memset(wa->local_cfg_addr, 0, sizeof(wa->local_cfg_addr));
    memset(wa->local_cfg_count, 0, sizeof(wa->local_cfg_count));

    for (int r = wa->region_start; r < wa->region_end; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        if (region->executable) continue;
        size_t size = region->end - region->start;
        if (size < 0x40 || size > MAX_SCAN_SIZE) continue;
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;

        uint8_t *base = (uint8_t *)region->start;
        for (size_t off = 0; off <= size - 0x40; off += 8) {
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; break; }

            uintptr_t val = *(volatile uintptr_t *)(base + off);
            if (val == 0) { g_in_safe_access = 0; continue; }

            uintptr_t obj_addr = (uintptr_t)(base + off);

            // --- RoleInfo (slot 0) ---
            if (val == wa->target_klass[0] && wa->local_ri_count < MAX_CACHED_ROLEINFO
                && off + 0x100 <= size) {
                int32_t roleId = *(volatile int32_t *)(obj_addr + 0x10);
                int32_t maxHp  = *(volatile int32_t *)(obj_addr + 0x14);
                int32_t curHp  = *(volatile int32_t *)(obj_addr + 0x18);
                int32_t level  = *(volatile int32_t *)(obj_addr + 0x24);
                if (roleId >= 0 && roleId <= 200 && maxHp >= 0 && maxHp <= 99999
                    && curHp >= 0 && curHp <= 99999 && level >= 0 && level <= 100) {
                    uintptr_t monitor = *(volatile uintptr_t *)(obj_addr + 8);
                    if (monitor == 0 || monitor >= 0x10000) {
                        wa->local_roleinfo[wa->local_ri_count++] = obj_addr;
                    }
                }
                g_in_safe_access = 0; continue;
            }

            // --- RoleInfoToWar (slot 1) ---
            if (wa->target_klass[1] && val == wa->target_klass[1]
                && wa->local_wi_count < MAX_CACHED_WARINFO && off + 0x80 <= size) {
                int32_t hp    = *(volatile int32_t *)(obj_addr + 0x10);
                int32_t maxHp = *(volatile int32_t *)(obj_addr + 0x14);
                int32_t level = *(volatile int32_t *)(obj_addr + 0x20);
                if (hp >= 0 && hp <= 999999 && maxHp >= 0 && maxHp <= 999999
                    && level >= 0 && level <= 100) {
                    wa->local_warinfo[wa->local_wi_count++] = obj_addr;
                }
                g_in_safe_access = 0; continue;
            }

            // --- 3 个 Config 类 (slots 2,3,4) ---
            for (int c = 0; c < 3; c++) {
                if (wa->target_klass[2+c] && val == wa->target_klass[2+c]) {
                    uintptr_t dict_ptr = *(volatile uintptr_t *)(obj_addr + 0x10);
                    if (dict_ptr >= 0x10000) {
                        int32_t count = *(volatile int32_t *)(dict_ptr + 0x20);
                        if (count > 0 && count < 100000 && count > wa->local_cfg_count[c]) {
                            wa->local_cfg_count[c] = count;
                            wa->local_cfg_addr[c] = obj_addr;
                        }
                    }
                    break;
                }
            }
            g_in_safe_access = 0;
        }
    }
    g_in_safe_access = 0;
    return NULL;
}

// ========== JNI: 预加载内存数据 ==========
static char* do_prescan(void) {
    if (init_il2cpp_context() != 0) return strdup("\u274C il2cpp 初始化失败");
    
    // ====== 收集所有要查找的 klass 指针 ======
    // 0=RoleInfo, 1=RoleInfoToWar, 2=CardsConfig, 3=LostThingConfig, 4=MinionEquipConfig
    uintptr_t target_klass[PRESCAN_SLOTS] = {0};
    target_klass[0] = (uintptr_t)g_roleinfo_cls;
    target_klass[1] = g_warinfo_cls ? (uintptr_t)g_warinfo_cls : 0;
    
    const char *cfg_names[] = {"CardsConfig", "LostThingConfig", "MinionEquipConfig"};
    int cfg_types[] = {1, 2, 3};
    for (int c = 0; c < 3; c++) {
        Il2CppClass klass = fn_class_from_name(g_csharp_image, "", cfg_names[c]);
        target_klass[2 + c] = (uintptr_t)klass;
    }
    
    // 配置类: 记录最佳候选 (dict count 最大)
    uintptr_t cfg_best_addr[3] = {0};
    int32_t   cfg_best_count[3] = {0};
    
    // 重置缓存
    g_cached_count = 0;
    g_warinfo_count = 0;
    
    // ====== 多线程并行扫描所有内存区域 ======
    parse_maps();
    install_sigsegv_handler();
    
    // 分配工作线程参数
    int nthreads = NUM_SCAN_THREADS;
    if (g_region_count < nthreads) nthreads = g_region_count;
    if (nthreads < 1) nthreads = 1;
    
    PrescanWorkerArg workers[NUM_SCAN_THREADS];
    pthread_t tids[NUM_SCAN_THREADS];
    int regions_per_thread = g_region_count / nthreads;
    int remainder = g_region_count % nthreads;
    int offset = 0;
    
    for (int t = 0; t < nthreads; t++) {
        workers[t].region_start = offset;
        int chunk = regions_per_thread + (t < remainder ? 1 : 0);
        workers[t].region_end = offset + chunk;
        offset += chunk;
        memcpy(workers[t].target_klass, target_klass, sizeof(target_klass));
    }
    
    // 启动工作线程
    LOGI("[prescan] launching %d scan threads for %d regions", nthreads, g_region_count);
    for (int t = 0; t < nthreads; t++) {
        if (pthread_create(&tids[t], NULL, prescan_worker, &workers[t]) != 0) {
            LOGW("[prescan] pthread_create failed for thread %d, running inline", t);
            prescan_worker(&workers[t]);
            tids[t] = 0;
        }
    }
    
    // 等待所有线程完成
    for (int t = 0; t < nthreads; t++) {
        if (tids[t]) pthread_join(tids[t], NULL);
    }
    
    uninstall_sigsegv_handler();
    
    // ====== 合并各线程结果 ======
    for (int t = 0; t < nthreads; t++) {
        PrescanWorkerArg *wa = &workers[t];
        // 合并 RoleInfo
        for (int i = 0; i < wa->local_ri_count && g_cached_count < MAX_CACHED_ROLEINFO; i++) {
            LOGI("RoleInfo @ 0x%" PRIxPTR " (thread %d)", wa->local_roleinfo[i], t);
            g_cached_roleinfo[g_cached_count++] = wa->local_roleinfo[i];
        }
        // 合并 RoleInfoToWar
        for (int i = 0; i < wa->local_wi_count && g_warinfo_count < MAX_CACHED_WARINFO; i++) {
            LOGI("RoleInfoToWar @ 0x%" PRIxPTR " (thread %d)", wa->local_warinfo[i], t);
            g_cached_warinfo[g_warinfo_count++] = wa->local_warinfo[i];
        }
        // 合并 Config 最佳候选
        for (int c = 0; c < 3; c++) {
            if (wa->local_cfg_count[c] > cfg_best_count[c]) {
                cfg_best_count[c] = wa->local_cfg_count[c];
                cfg_best_addr[c] = wa->local_cfg_addr[c];
            }
        }
    }
    
    LOGI("[prescan] multi-thread done (%d threads): RoleInfo=%d, WarInfo=%d",
         nthreads, g_cached_count, g_warinfo_count);
    
    // ====== 保存配置类缓存 ======
    int cached = 0;
    for (int c = 0; c < 3; c++) {
        if (cfg_best_addr[c]) {
            set_config_cache(cfg_types[c], target_klass[2+c], cfg_best_addr[c]);
            cached++;
            LOGI("[prescan] %s @ %p (dict count=%d)", cfg_names[c],
                 (void*)cfg_best_addr[c], cfg_best_count[c]);
        } else if (get_cached_config(cfg_types[c], target_klass[2+c])) {
            cached++; // 之前已缓存且仍有效
        } else {
            LOGW("[prescan] No instance for %s", cfg_names[c]);
        }
    }
    
    // ====== 输出调试详情 ======
    int ri_count = g_cached_count;
    int wi_count = g_warinfo_count;
    
    if (ri_count > 0) {
        install_sigsegv_handler();
        for (int i = 0; i < g_cached_count; i++) {
            uintptr_t obj = g_cached_roleinfo[i];
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            int32_t gold = *(volatile int32_t *)(obj + OFF_CURGOLD);
            int32_t hp = *(volatile int32_t *)(obj + OFF_CURHP);
            int32_t maxhp = *(volatile int32_t *)(obj + OFF_MAXHP);
            g_in_safe_access = 0;
            LOGI("[prescan] RoleInfo[%d] @ %p: gold=%d hp=%d/%d", i, (void*)obj, gold, hp, maxhp);
        }
        uninstall_sigsegv_handler();
    }
    
    if (wi_count > 0) {
        install_sigsegv_handler();
        for (int i = 0; i < g_warinfo_count; i++) {
            uintptr_t wobj = g_cached_warinfo[i];
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) { g_in_safe_access = 0; continue; }
            int32_t hp = *(volatile int32_t *)(wobj + 0x10);
            int32_t maxHp = *(volatile int32_t *)(wobj + 0x14);
            uintptr_t war_equipts = *(volatile uintptr_t *)(wobj + 0x60);
            g_in_safe_access = 0;
            LOGI("[prescan] WarInfo[%d] @ %p: hp=%d/%d equipts=%p",
                 i, (void*)wobj, hp, maxHp, (void*)war_equipts);
        }
        uninstall_sigsegv_handler();
    }
    
    char *buf = (char *)malloc(256);
    snprintf(buf, 256, "\u2705 预加载完成: %d个角色, %d个战斗角色, %d/3个配置", ri_count, wi_count, cached);
    return buf;
}

static jstring JNICALL jni_prescan(JNIEnv *env, jclass clazz) {
    LOGI("[JNI] nativePreScan");
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    char *result = do_prescan();
    pthread_mutex_unlock(&g_hack_mutex);
    jstring jresult = (*env)->NewStringUTF(env, result);
    free(result);
    return jresult;
}

// ========== JNI: 读取当前物品列表 ==========
static jstring JNICALL jni_get_current_items(JNIEnv *env, jclass clazz, jint type) {
    LOGI("[JNI] nativeGetCurrentItems(%d)", (int)type);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "[]");
    char *json = do_get_current_items((int)type);
    pthread_mutex_unlock(&g_hack_mutex);
    jstring result = (*env)->NewStringUTF(env, json);
    free(json);
    return result;
}

// ========== JNI: 删除卡牌 ==========
static jstring JNICALL jni_remove_card(JNIEnv *env, jclass clazz, jint card_id) {
    LOGI("[JNI] nativeRemoveCard(%d)", (int)card_id);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    char buf[128];
    int ret = do_remove_card((int)card_id);
    if (ret > 0) snprintf(buf, sizeof(buf), "\u2705 已删除卡牌 %d", (int)card_id);
    else if (ret == 0) snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到卡牌 %d", (int)card_id);
    else snprintf(buf, sizeof(buf), "\u274C 删除失败");
    pthread_mutex_unlock(&g_hack_mutex);
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 删除祝福 ==========
static jstring JNICALL jni_remove_lostthing(JNIEnv *env, jclass clazz, jint lt_id) {
    LOGI("[JNI] nativeRemoveLostThing(%d)", (int)lt_id);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    char buf[128];
    int ret = do_remove_lostthing((int)lt_id);
    if (ret > 0) snprintf(buf, sizeof(buf), "\u2705 已删除祝福 %d", (int)lt_id);
    else if (ret == 0) snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到祝福 %d", (int)lt_id);
    else snprintf(buf, sizeof(buf), "\u274C 删除失败");
    pthread_mutex_unlock(&g_hack_mutex);
    return (*env)->NewStringUTF(env, buf);
}

// ========== JNI: 设置卡牌数量 ==========
static jstring JNICALL jni_set_card_count(JNIEnv *env, jclass clazz, jint card_id, jint count) {
    LOGI("[JNI] nativeSetCardCount(%d, %d)", (int)card_id, (int)count);
    if (pthread_mutex_trylock(&g_hack_mutex) != 0)
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中...");
    char *result = do_set_card_count((int)card_id, (int)count);
    pthread_mutex_unlock(&g_hack_mutex);
    jstring js = (*env)->NewStringUTF(env, result);
    free(result);
    return js;
}

// ========== DLC 解锁 JNI 方法 ==========
static jstring JNICALL jni_unlock_dlc(JNIEnv *env, jclass clazz) {
    LOGI("[JNI] nativeUnlockDLC");
    if (pthread_mutex_trylock(&g_hack_mutex) != 0) {
        LOGW("[JNI] nativeUnlockDLC busy");
        return (*env)->NewStringUTF(env, "\u23F3 操作进行中，请稍候...");
    }
    int result = do_unlock_all_dlc();
    pthread_mutex_unlock(&g_hack_mutex);
    char buf[256];
    if (result > 0)
        snprintf(buf, sizeof(buf), "\u2705 DLC解锁成功: %d/16 角色已解锁\n请【返回主菜单】重新进入角色选择界面", result);
    else if (result == -2)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 未找到 ProtoLogin 实例(请先进入主菜单)");
    else if (result == -3)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F ProtoLogin 实例无效(SIGSEGV)，请稍后重试");
    else if (result == 0)
        snprintf(buf, sizeof(buf), "\u26A0\uFE0F 0/16 角色解锁 (游戏可能未完全加载，请稍后重试)");
    else
        snprintf(buf, sizeof(buf), "\u274C DLC 解锁失败 (code=%d)", result);
    return (*env)->NewStringUTF(env, buf);
}

static JNINativeMethod g_jni_methods[] = {
    { "nativeModifyGold",      "(I)Ljava/lang/String;",     (void *)jni_modify_gold },
    { "nativeResetSkillCD",    "()Ljava/lang/String;",      (void *)jni_reset_skill_cd },
    { "nativeModifyHp",        "(I)Ljava/lang/String;",     (void *)jni_modify_hp },
    { "nativeModifyMp",        "(I)Ljava/lang/String;",     (void *)jni_modify_mp },
    { "nativeModifyAction",    "(I)Ljava/lang/String;",     (void *)jni_modify_action },
    { "nativeModifyHandcards", "(I)Ljava/lang/String;",     (void *)jni_modify_handcards },
    { "nativeAddEquipment",    "(I)Ljava/lang/String;",     (void *)jni_add_equipment },
    { "nativeAddLostThing",    "(I)Ljava/lang/String;",     (void *)jni_add_lostthing },
    { "nativeAddCard",         "(I)Ljava/lang/String;",     (void *)jni_add_card },
    { "nativeModifyAll",       "(IIIII)Ljava/lang/String;", (void *)jni_modify_all },
    { "nativeEnumItems",       "(I)Ljava/lang/String;",     (void *)jni_enum_items },
    { "nativeModifyEquipSlots","(I)Ljava/lang/String;",     (void *)jni_modify_equip_slots },
    { "nativePreScan",         "()Ljava/lang/String;",      (void *)jni_prescan },
    { "nativeGetCurrentItems", "(I)Ljava/lang/String;",     (void *)jni_get_current_items },
    { "nativeRemoveCard",      "(I)Ljava/lang/String;",     (void *)jni_remove_card },
    { "nativeRemoveLostThing", "(I)Ljava/lang/String;",     (void *)jni_remove_lostthing },
    { "nativeSetCardCount",    "(II)Ljava/lang/String;",    (void *)jni_set_card_count },
    { "nativeUnlockDLC",       "()Ljava/lang/String;",      (void *)jni_unlock_dlc },
};

// ========== 通过 JNI 加载嵌入的 DEX 并创建悬浮菜单 ==========
#ifdef OVERLAY_DEX
static void create_overlay_menu(void) {
    LOGI("[overlay] Creating in-game overlay menu...");

    // 1. 获取 JavaVM
    typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
    JNI_GetCreatedJavaVMs_t getVMs = NULL;

    // 尝试从 libart.so 获取
    void *art = dlopen("libart.so", RTLD_NOLOAD);
    if (art) getVMs = (JNI_GetCreatedJavaVMs_t)dlsym(art, "JNI_GetCreatedJavaVMs");
    if (!getVMs) {
        // 尝试 libnativehelper.so
        void *nh = dlopen("libnativehelper.so", RTLD_NOLOAD);
        if (nh) getVMs = (JNI_GetCreatedJavaVMs_t)dlsym(nh, "JNI_GetCreatedJavaVMs");
    }
    if (!getVMs) {
        LOGE("[overlay] Cannot find JNI_GetCreatedJavaVMs");
        return;
    }

    JavaVM *jvm = NULL;
    jsize vm_count = 0;
    if (getVMs(&jvm, 1, &vm_count) != JNI_OK || vm_count == 0 || !jvm) {
        LOGE("[overlay] No JavaVM found");
        return;
    }
    LOGI("[overlay] JavaVM: %p", jvm);

    // 2. 附加线程
    JNIEnv *env = NULL;
    int attached = 0;
    jint res = (*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_6);
    if (res != JNI_OK) {
        JavaVMAttachArgs args = { JNI_VERSION_1_6, "GoldHackOverlay", NULL };
        if ((*jvm)->AttachCurrentThread(jvm, &env, &args) != JNI_OK) {
            LOGE("[overlay] AttachCurrentThread failed");
            return;
        }
        attached = 1;
    }

    // 3. 用 InMemoryDexClassLoader 加载 DEX（API 26+）
    jclass ByteBuffer_cls = (*env)->FindClass(env, "java/nio/ByteBuffer");
    jmethodID BB_allocateDirect = (*env)->GetStaticMethodID(env, ByteBuffer_cls,
        "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
    jobject dex_buf = (*env)->CallStaticObjectMethod(env, ByteBuffer_cls,
        BB_allocateDirect, (jint)overlay_dex_data_len);
    // 拷贝 DEX 数据到 DirectByteBuffer
    void *buf_addr = (*env)->GetDirectBufferAddress(env, dex_buf);
    memcpy(buf_addr, overlay_dex_data, overlay_dex_data_len);

    // 获取应用的 ClassLoader（native 线程的 FindClass 只能找系统类）
    // 通过 ActivityThread.currentActivityThread().getApplication().getClassLoader()
    jclass AT_cls = (*env)->FindClass(env, "android/app/ActivityThread");
    jmethodID AT_current = (*env)->GetStaticMethodID(env, AT_cls,
        "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject actThread = (*env)->CallStaticObjectMethod(env, AT_cls, AT_current);
    jmethodID AT_getApp = (*env)->GetMethodID(env, AT_cls,
        "getApplication", "()Landroid/app/Application;");
    jobject app = (*env)->CallObjectMethod(env, actThread, AT_getApp);
    if (!app) {
        LOGE("[overlay] ActivityThread.getApplication() returned null");
        goto cleanup;
    }
    jclass Context_cls = (*env)->FindClass(env, "android/content/Context");
    jmethodID getCL = (*env)->GetMethodID(env, Context_cls,
        "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject appCL = (*env)->CallObjectMethod(env, app, getCL);
    LOGI("[overlay] App ClassLoader: %p", appCL);

    // 获取 ClassLoader.loadClass 方法（后续多处使用）
    jclass ClassLoader_cls = (*env)->FindClass(env, "java/lang/ClassLoader");
    jmethodID loadClass = (*env)->GetMethodID(env, ClassLoader_cls,
        "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");

    // 创建 InMemoryDexClassLoader（使用 appCL 作为 parent）
    jclass IMDCL_cls = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        LOGE("[overlay] InMemoryDexClassLoader not found (API < 26?)");
        goto cleanup;
    }
    jmethodID IMDCL_ctor = (*env)->GetMethodID(env, IMDCL_cls, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexLoader = (*env)->NewObject(env, IMDCL_cls, IMDCL_ctor, dex_buf, appCL);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("[overlay] Failed to create InMemoryDexClassLoader");
        goto cleanup;
    }
    LOGI("[overlay] DexClassLoader created (parent=appCL)");

    // 4. 加载 OverlayMenu 类
    jstring className = (*env)->NewStringUTF(env, "com.hack.menu.OverlayMenu");
    jclass menuClass = (jclass)(*env)->CallObjectMethod(env, dexLoader, loadClass, className);
    if ((*env)->ExceptionCheck(env) || !menuClass) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("[overlay] Failed to load OverlayMenu class");
        goto cleanup;
    }
    LOGI("[overlay] OverlayMenu class loaded");

    // 5. 注册 native 方法
    if ((*env)->RegisterNatives(env, menuClass, g_jni_methods,
            sizeof(g_jni_methods) / sizeof(g_jni_methods[0])) != JNI_OK) {
        LOGE("[overlay] RegisterNatives failed");
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        goto cleanup;
    }
    LOGI("[overlay] Native methods registered");

    // 6. 获取 Activity（通过 app ClassLoader 加载 UnityPlayer）
    jstring upClassName = (*env)->NewStringUTF(env, "com.unity3d.player.UnityPlayer");
    jclass unityPlayer = (jclass)(*env)->CallObjectMethod(env, appCL, loadClass, upClassName);
    if ((*env)->ExceptionCheck(env) || !unityPlayer) {
        (*env)->ExceptionClear(env);
        LOGW("[overlay] UnityPlayer not found via appCL, trying loadClass on dexLoader...");
        // fallback: try with dexLoader's parent delegation
        unityPlayer = (jclass)(*env)->CallObjectMethod(env, dexLoader, loadClass, upClassName);
        if ((*env)->ExceptionCheck(env) || !unityPlayer) {
            (*env)->ExceptionClear(env);
            LOGE("[overlay] UnityPlayer class not found at all");
            goto cleanup;
        }
    }
    jfieldID actField = (*env)->GetStaticFieldID(env, unityPlayer,
        "currentActivity", "Landroid/app/Activity;");
    jobject activity = (*env)->GetStaticObjectField(env, unityPlayer, actField);
    if (!activity) {
        LOGE("[overlay] UnityPlayer.currentActivity is null");
        goto cleanup;
    }
    LOGI("[overlay] Activity: %p", activity);

    // 7. 调用 OverlayMenu.create(activity)
    jmethodID createMethod = (*env)->GetStaticMethodID(env, menuClass,
        "create", "(Landroid/app/Activity;)V");
    (*env)->CallStaticVoidMethod(env, menuClass, createMethod, activity);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        LOGE("[overlay] OverlayMenu.create() failed");
        goto cleanup;
    }
    LOGI("[overlay] OverlayMenu.create() called successfully!");

cleanup:
    // 注意: 不 DetachCurrentThread —— 线程会继续存活以处理后续 JNI 调用
    if (attached) {
        // 保持 attached 以便 JNI 回调可用
        LOGI("[overlay] Thread stays attached for JNI callbacks");
    }
}
#endif /* OVERLAY_DEX */

// ========== 后台 DLC 持续解锁线程 ==========
// 目的: 尽早在游戏初始化完成后自动调用 AddDLC，
// 确保在用户进入角色选择界面之前就完成解锁。
// 同时持续运行以防游戏重置 DLC 数据。
static void *dlc_monitor_thread(void *arg) {
    (void)arg;
    LOGI("[dlc-monitor] DLC monitor started, waiting 8s for game login...");
    sleep(8); // 等待游戏完成登录
    
    int attempts = 0;
    int max_attempts = 30; // 最多尝试 30 次（~90秒）
    
    while (attempts < max_attempts) {
        attempts++;
        
        if (g_dlc_unlocked) {
            LOGI("[dlc-monitor] DLC already unlocked, checking persistence (attempt %d)...", attempts);
        } else {
            LOGI("[dlc-monitor] Attempt %d/%d to unlock DLC...", attempts, max_attempts);
        }
        
        // 互斥锁 — 防止和手动按钮冲突
        if (pthread_mutex_trylock(&g_hack_mutex) != 0) {
            LOGI("[dlc-monitor] Mutex busy, skipping this round");
            sleep(3);
            continue;
        }
        
        int result = do_unlock_all_dlc();
        pthread_mutex_unlock(&g_hack_mutex);
        
        if (result == -3) {
            // 实例无效（SIGSEGV），快速重试
            LOGW("[dlc-monitor] Invalid instance, retrying in 2s...");
            sleep(2);
            continue;
        } else if (result == -2) {
            // ProtoLogin 未找到，游戏可能还在加载
            LOGI("[dlc-monitor] ProtoLogin not found yet, retrying in 3s...");
            sleep(3);
            continue;
        } else if (result > 0) {
            LOGI("[dlc-monitor] ★ %d/16 roles unlocked! Monitor done.", result);
            // v6.28b: 成功后退出 — 持续调用 il2cpp API 从后台线程会导致崩溃
            break;
        } else {
            // result == 0: 所有策略都无效，可能游戏未完全加载
            LOGW("[dlc-monitor] 0 roles unlocked, retrying in 5s...", result);
            sleep(5);
            continue;
        }
    }
    
    LOGI("[dlc-monitor] DLC monitor finished (%d attempts)", attempts);
    return NULL;
}

// ========== 主工作线程 ==========
static void *hack_thread(void *arg) {
    int target_gold = (int)(intptr_t)arg;
    LOGI("=== GoldHack started, target_gold=%d ===", target_gold);
    
    // v6.34: 立即尝试从缓存安装 Execute hook (在游戏加载 DLC 状态之前!)
    // 首次运行会失败 (无缓存), 重启后 <1 秒内安装
    try_early_execute_hook();
    
    LOGI("Waiting %d seconds for game to load...", WAIT_SECONDS);
    sleep(WAIT_SECONDS);

    // 1. 解析内存映射
    if (parse_maps() != 0) {
        LOGE("Failed to parse memory maps");
        return NULL;
    }

    // 2. 查找 libil2cpp.so
    uintptr_t il2cpp_base = find_il2cpp_base();
    if (!il2cpp_base) {
        LOGE("libil2cpp.so not found in memory");
        return NULL;
    }
    // v6.34: 保存基址用于 Execute 偏移缓存
    g_il2cpp_base_for_cache = il2cpp_base;

    // 3. 尝试获取 il2cpp API（优先从缓存加载）
    LOGI("Attempting to resolve il2cpp APIs...");
    
    int api_from_cache = 0;
    // 方法0: 从缓存文件加载（最快）
    if (load_api_cache(il2cpp_base) == 0) {
        LOGI("All APIs restored from cache (<1ms)");
        api_from_cache = 1;
    }
    // 方法1: 尝试 dlsym（无保护的情况下）
    else if (try_dlsym_apis() == 0) {
        LOGI("All APIs resolved via dlsym");
        save_api_cache(il2cpp_base);
    } else {
        // 方法2: 内存扫描（绕过 MHP 保护）
        LOGI("dlsym failed, falling back to memory scan...");
        scan_api_strings();
        if (resolve_apis_from_pairs() != 0) {
            LOGE("Failed to resolve all required APIs");
            
            // 打印哪些 API 缺失
            for (int i = 0; g_api_table[i].name; i++) {
                if (*g_api_table[i].func_ptr == NULL) {
                    LOGE("  MISSING: %s", g_api_table[i].name);
                }
            }
            return NULL;
        }
        save_api_cache(il2cpp_base);
    }

    // 4. 验证所有 API 已就位
    int missing_critical = 0;
    int missing_optional = 0;
    for (int i = 0; g_api_table[i].name; i++) {
        if (*g_api_table[i].func_ptr == NULL) {
            // 前6个是核心 API，必须存在
            if (i < 6) {
                LOGE("CRITICAL API %s is NULL", g_api_table[i].name);
                missing_critical++;
            } else {
                LOGW("Optional API %s is NULL (non-fatal)", g_api_table[i].name);
                missing_optional++;
            }
        } else {
            LOGI("API ready: %s @ %p", g_api_table[i].name, *g_api_table[i].func_ptr);
        }
    }
    if (missing_critical > 0) {
        LOGE("Missing %d critical APIs, aborting", missing_critical);
        return NULL;
    }
    if (missing_optional > 0) {
        LOGW("%d optional APIs missing, some features may not work", missing_optional);
    }

    // 确保信号处理器已恢复为 MHP 原始状态（不用 SIG_DFL，MHP 的 trampoline 可能需要自己的处理器）
    uninstall_sigsegv_handler();
    // 给内核/ART 一点时间恢复信号状态
    usleep(100000); // 100ms

    // 5. 初始化 il2cpp 上下文（domain/image/class 缓存到全局）
    if (init_il2cpp_context() != 0) {
        LOGE("Failed to initialize il2cpp context");
        return NULL;
    }
    LOGI("il2cpp context initialized");

    // 5.5 枚举游戏类（调试：分析更新检查和登录机制）
    enumerate_game_classes();

    // 5.6 安装版本检查绕过
    bypass_version_check();
    
    // 5.7 安装 DLC/职业解锁绕过
    bypass_dlc_lock();

    // 5.8 v6.28: restore auto DLC monitor thread (v6.9 had this)
    {
        pthread_t dlc_tid;
        if (pthread_create(&dlc_tid, NULL, dlc_monitor_thread, NULL) == 0) {
            pthread_detach(dlc_tid);
            LOGI("[dlc-monitor] Background DLC unlock thread started (v6.28 restored)");
        } else {
            LOGW("[dlc-monitor] Failed to create DLC monitor thread");
        }
    }

    // 6. 启动游戏内悬浮菜单
#ifdef OVERLAY_DEX
    LOGI("=== Creating overlay menu ===");
    create_overlay_menu();
    LOGI("=== Overlay menu launched, waiting for user interaction ===");
    // 线程保持存活以处理 JNI 回调
    // 菜单按钮触发 native 方法时会在 Java 线程中调用 do_modify_gold / do_reset_skill_cd
    while (1) { sleep(3600); }
#else
    // 无 overlay 模式：直接执行一次性修改
    LOGI("=== Modifying gold to %d & resetting skill CDs (one-shot mode) ===", target_gold);
    int count = modify_gold(target_gold);
    
    if (count > 0) {
        LOGI("=== SUCCESS: Modified %d RoleInfo instance(s) ===", count);
    } else if (count == 0) {
        LOGW("=== No RoleInfo instances found (not in a game session?) ===");
        LOGI("Will retry in 10 seconds...");
        sleep(10);
        parse_maps(); // 重新解析
        count = modify_gold(target_gold);
        if (count > 0) {
            LOGI("=== RETRY SUCCESS: Modified %d instance(s) ===", count);
        } else {
            LOGW("=== Retry failed. Game may not be in a session. ===");
        }
    } else {
        LOGE("=== Gold modification failed ===");
    }
#endif

    LOGI("=== GoldHack thread finished ===");
    return NULL;
}

// ========== Anti-kill: 拦截 MHP/SecSDK 反篡改自杀 ==========
// MHP/SecSDK 检测到 APK 被修改后，通过 Process.killProcess() -> kill(getpid(), SIGKILL)
// 杀死进程。我们通过 inline hook libc 的 kill() 函数来拦截自杀。

static int hook_kill_func(pid_t pid, int sig) {
    pid_t self = getpid();
    if (pid == self && (sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV || sig == SIGTERM || sig == SIGQUIT)) {
        LOGW("[anti-kill] Blocked self-kill (sig=%d) from anti-tamper check", sig);
        return 0;  // 假装成功但不执行
    }
    // 其他 kill 调用使用原始 syscall
    return (int)syscall(__NR_kill, pid, sig);
}

// v6.33: hook tgkill — 反篡改使用 tgkill(pid, tid, SIGSEGV) 攻击我们的线程
static int hook_tgkill_func(pid_t tgid, pid_t tid, int sig) {
    pid_t self = getpid();
    if (tgid == self && (sig == SIGSEGV || sig == SIGABRT || sig == SIGKILL || sig == SIGTERM)) {
        LOGW("[anti-kill] Blocked tgkill(tgid=%d, tid=%d, sig=%d) from anti-tamper", tgid, tid, sig);
        return 0;
    }
    return (int)syscall(__NR_tgkill, tgid, tid, sig);
}

// v6.33: 安装 SIGSEGV/SIGABRT 信号处理器作为最后防线
static volatile int g_anti_tamper_signal_count = 0;
static struct sigaction g_old_sigsegv_action;
static struct sigaction g_old_sigabrt_action;

static void anti_tamper_signal_handler(int signo, siginfo_t *info, void *context) {
    // 检查信号来源：SI_TKILL 表示是被其他线程/进程发送的
    if (info && (info->si_code == SI_TKILL || info->si_code == SI_USER)) {
        g_anti_tamper_signal_count++;
        if (g_anti_tamper_signal_count <= 20) {
            LOGW("[anti-kill] Caught anti-tamper signal %d (code=%d, sender_pid=%d) — IGNORED #%d",
                 signo, info->si_code, info->si_pid, g_anti_tamper_signal_count);
        }
        return;  // 忽略来自 tkill/kill 的信号
    }
    // 真正的硬件异常（如 SEGV_MAPERR），调用原始处理器
    struct sigaction *old = (signo == SIGSEGV) ? &g_old_sigsegv_action : &g_old_sigabrt_action;
    if (old->sa_flags & SA_SIGINFO) {
        if (old->sa_sigaction) old->sa_sigaction(signo, info, context);
    } else {
        if (old->sa_handler && old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
            old->sa_handler(signo);
        } else {
            // 恢复默认处理并重新发送
            struct sigaction dfl = {0};
            dfl.sa_handler = SIG_DFL;
            sigaction(signo, &dfl, NULL);
            raise(signo);
        }
    }
}

static void install_signal_defense(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = anti_tamper_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGSEGV, &sa, &g_old_sigsegv_action) == 0) {
        LOGI("[anti-kill] SIGSEGV handler installed (defense against tgkill)");
    }
    if (sigaction(SIGABRT, &sa, &g_old_sigabrt_action) == 0) {
        LOGI("[anti-kill] SIGABRT handler installed (defense against tgkill)");
    }
}

// v6.32: hook exit/_exit — 反篡改检测到 kill() 被 hook 后改用 System.exit()
// System.exit() → Runtime.halt() → _exit() 或 exit()
// 注意: exit/_exit 是 noreturn 函数, 调用者假设它们永不返回.
// 所以我们不能直接 return, 而是让线程永远 sleep.
static void hook_exit_func(int status) {
    LOGW("[anti-kill] Blocked exit(%d) from anti-tamper, suspending thread", status);
    while (1) sleep(3600);  // 挂起反篡改线程
}

static void hook__exit_func(int status) {
    LOGW("[anti-kill] Blocked _exit(%d) from anti-tamper, suspending thread", status);
    while (1) sleep(3600);  // 挂起反篡改线程
}

// 通用 inline hook 安装函数 (无 trampoline, 16 bytes)
static int install_simple_hook(void *target, void *hook, const char *name) {
    if (!target || !hook) return -1;
    uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
            LOGE("[anti-kill] mprotect failed for %s: %s", name, strerror(errno));
            return -1;
        }
    }
    uint32_t *code = (uint32_t *)target;
    code[0] = 0x58000050;  // LDR X16, [PC, #8]
    code[1] = 0xD61F0200;  // BR X16
    *(uint64_t *)(code + 2) = (uint64_t)hook;
    __builtin___clear_cache((char *)target, (char *)((uint8_t*)target + 16));
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);
    LOGI("[anti-kill] %s @ %p hooked → %p", name, target, hook);
    return 0;
}

static void install_kill_hook(void) {
    // 查找 libc 的 kill() 函数
    void *kill_addr = dlsym(RTLD_DEFAULT, "kill");
    if (!kill_addr) {
        LOGE("[anti-kill] dlsym(kill) failed");
        return;
    }
    LOGI("[anti-kill] libc kill() @ %p, hook @ %p", kill_addr, (void*)hook_kill_func);

    // 使 kill() 代码页可写
    uintptr_t page = (uintptr_t)kill_addr & ~(uintptr_t)0xFFF;
    if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("[anti-kill] mprotect RWX failed: %s", strerror(errno));
        // 尝试不带 EXEC 的 mprotect
        if (mprotect((void *)page, 0x2000, PROT_READ | PROT_WRITE) != 0) {
            LOGE("[anti-kill] mprotect RW failed: %s", strerror(errno));
            return;
        }
    }

    // 在 kill() 入口写入跳转到 hook 的指令:
    // LDR X16, [PC, #8]   (0x58000050)
    // BR  X16              (0xD61F0200)
    // .quad hook_addr      (8 bytes)
    uint32_t *code = (uint32_t *)kill_addr;
    code[0] = 0x58000050;  // LDR X16, [PC, #8]
    code[1] = 0xD61F0200;  // BR X16
    uint64_t *target = (uint64_t *)(code + 2);
    *target = (uint64_t)(void*)hook_kill_func;

    // 刷新指令缓存
    __builtin___clear_cache((char *)kill_addr, (char *)((uint8_t*)kill_addr + 16));

    // 恢复页保护
    mprotect((void *)page, 0x2000, PROT_READ | PROT_EXEC);

    LOGI("[anti-kill] kill() hooked successfully");
    
    // v6.32: 也 hook exit() 和 _exit() — 反篡改在 kill() 被拦截后改用 System.exit(10)
    void *exit_addr = dlsym(RTLD_DEFAULT, "exit");
    if (exit_addr) install_simple_hook(exit_addr, (void*)hook_exit_func, "exit()");
    
    void *_exit_addr = dlsym(RTLD_DEFAULT, "_exit");
    if (_exit_addr) install_simple_hook(_exit_addr, (void*)hook__exit_func, "_exit()");
    
    // 也尝试 _Exit (C99)
    void *Exit_addr = dlsym(RTLD_DEFAULT, "_Exit");
    if (Exit_addr && Exit_addr != _exit_addr) 
        install_simple_hook(Exit_addr, (void*)hook__exit_func, "_Exit()");
    
    // v6.33: hook tgkill — 反篡改使用 tgkill 发送 SIGSEGV 给我们的线程
    void *tgkill_addr = dlsym(RTLD_DEFAULT, "tgkill");
    if (tgkill_addr) install_simple_hook(tgkill_addr, (void*)hook_tgkill_func, "tgkill()");
    
    // v6.33: 安装信号处理器作为最后防线
    install_signal_defense();
}

// ========== .so 入口（constructor）==========
__attribute__((constructor))
void gold_hack_init(void) {
    LOGI("=== libgoldhack.so loaded ===");

    // 第一时间安装 kill() hook，防止反篡改保护杀进程
    install_kill_hook();
    
    pthread_t tid;
    int ret = pthread_create(&tid, NULL, hack_thread, (void*)(intptr_t)TARGET_GOLD);
    if (ret != 0) {
        LOGE("Failed to create hack thread: %d", ret);
    } else {
        pthread_detach(tid);
        LOGI("Hack thread started (target_gold=%d)", TARGET_GOLD);
    }
}
