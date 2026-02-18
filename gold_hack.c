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
#define WAIT_SECONDS    5          // 等待游戏加载的秒数，编译时可用 -DWAIT_SECONDS=20 覆盖
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

#define LOG_TAG "GoldHack"
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

static ApiEntry g_api_table[] = {
    { "il2cpp_domain_get",             (void**)&fn_domain_get },
    { "il2cpp_thread_attach",          (void**)&fn_thread_attach },
    { "il2cpp_domain_get_assemblies",  (void**)&fn_domain_get_assemblies },
    { "il2cpp_assembly_get_image",     (void**)&fn_assembly_get_image },
    { "il2cpp_image_get_name",         (void**)&fn_image_get_name },
    { "il2cpp_class_from_name",        (void**)&fn_class_from_name },
    { NULL, NULL }
};

#define API_COUNT 6

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
static sigjmp_buf g_jmpbuf;
static volatile int g_in_safe_access = 0;

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
    
    if (loaded == API_COUNT) {
        LOGI("[cache] All %d APIs restored from cache", loaded);
        return 0;
    }
    
    LOGW("[cache] Only %d/%d APIs restored, falling back to scan", loaded, API_COUNT);
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
    return (resolved >= API_COUNT) ? 0 : -1;
}

// ========== il2cpp 运行时上下文（初始化后全局缓存）==========
static Il2CppDomain  g_domain       = NULL;
static Il2CppImage   g_csharp_image = NULL;
static Il2CppClass   g_roleinfo_cls = NULL;

// 初始化 il2cpp 上下文（domain / image / class），只需调用一次
static int init_il2cpp_context(void) {
    if (g_roleinfo_cls) return 0;  // 已初始化

    LOGI("Calling il2cpp_domain_get @ %p", (void*)fn_domain_get);
    g_domain = fn_domain_get();
    if (!g_domain) { LOGE("il2cpp_domain_get returned NULL"); return -1; }
    LOGI("Domain: %p, calling thread_attach...", g_domain);
    fn_thread_attach(g_domain);
    LOGI("Attached to il2cpp domain");

    size_t asm_count = 0;
    Il2CppAssembly *assemblies = fn_domain_get_assemblies(g_domain, &asm_count);
    if (!assemblies || asm_count == 0) { LOGE("No assemblies found"); return -1; }
    LOGI("Found %zu assemblies", asm_count);

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
    if (!g_csharp_image) { LOGE("Assembly-CSharp.dll not found"); return -1; }
    LOGI("Found Assembly-CSharp.dll: %p", g_csharp_image);

    g_roleinfo_cls = fn_class_from_name(g_csharp_image, "", "RoleInfo");
    if (!g_roleinfo_cls) { LOGE("RoleInfo class not found"); return -1; }
    LOGI("RoleInfo klass: %p", g_roleinfo_cls);
    return 0;
}

// ========== RoleInfo 实例缓存（避免每次全量扫描）==========
#define MAX_CACHED_ROLEINFO 8
static uintptr_t g_cached_roleinfo[MAX_CACHED_ROLEINFO];
static int        g_cached_count = 0;

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
static uintptr_t alloc_int32_szarray(uintptr_t old_arr, int new_cap) {
    // SZArray 头: klass(8) + monitor(8) + bounds(8,=0) + max_length(8) + elements(new_cap * 4)
    size_t header_sz = 0x20;
    size_t total = header_sz + (size_t)new_cap * 4;
    // 页对齐 mmap
    size_t page_sz = 4096;
    size_t alloc_sz = (total + page_sz - 1) & ~(page_sz - 1);
    void *mem = mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        LOGE("  alloc_int32_szarray: mmap failed (size=%zu)", alloc_sz);
        return 0;
    }
    memset(mem, 0, alloc_sz);
    uintptr_t arr = (uintptr_t)mem;

    // 复制 klass 和 monitor 从旧数组
    if (old_arr > 0x10000) {
        *(volatile uintptr_t *)(arr + 0x00) = *(volatile uintptr_t *)(old_arr + 0x00); // klass
        *(volatile uintptr_t *)(arr + 0x08) = *(volatile uintptr_t *)(old_arr + 0x08); // monitor
    }
    // bounds = NULL (SZArray)
    *(volatile uintptr_t *)(arr + 0x10) = 0;
    // max_length
    *(volatile uintptr_t *)(arr + 0x18) = (uintptr_t)new_cap;

    LOGI("  alloc_int32_szarray: new arr @ %p, cap=%d, total=%zu", mem, new_cap, alloc_sz);
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
    
    // 检查是否已存在 (在扩容之前检查)
    for (int i = 0; i < size; i++) {
        if (elem_base[i] == item_id) {
            LOGI("  Item %d already in list at [%d]", item_id, i);
            return 0;
        }
    }
    
    // 容量不够时 → 分配新数组并替换
    if (max_length == 0 || (uintptr_t)size >= max_length) {
        int new_cap = (int)(max_length == 0 ? 16 : max_length * 2);
        if (new_cap < size + 4) new_cap = size + 4;
        if (new_cap > 200) new_cap = 200;
        
        LOGI("  Expanding: old cap=%d, new cap=%d, copying %d elements",
             (int)max_length, new_cap, size);
        
        uintptr_t new_arr = alloc_int32_szarray(items, new_cap);
        if (!new_arr) return -1;
        
        // 拷贝旧元素到新数组 (+0x20 = elements)
        int32_t *new_elem = (int32_t *)(new_arr + 0x20);
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
        int ret = add_item_to_int_list(equip_list, equip_id);
        g_in_safe_access = 0;
        if (ret >= 0) count++;
    }
    uninstall_sigsegv_handler();
    LOGI("do_add_equipment: added equip %d to %d instance(s)", equip_id, count);
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
// cardsLibraryAll 是 List<CardInfoInDeck>，每个元素有 id(+0x10) 和 idx(+0x14)
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
        
        // 向 cardsBattle (List<Int32>) 添加卡牌（战斗用卡组）
        uintptr_t battle_cards = *(volatile uintptr_t *)(obj_addr + 0x100); // cardsBattle
        if (battle_cards > 0x10000) {
            add_item_to_int_list(battle_cards, card_id);
        }
        
        g_in_safe_access = 0;
        count++;
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
        if (probe == 0) {
            max_length = *(volatile uintptr_t *)(items + 0x18);
            elem_base = (int32_t *)(items + 0x20);
        } else if (probe > 0 && probe <= 200000) {
            max_length = probe;
            elem_base = (int32_t *)(items + 0x18);
        } else {
            uint32_t lo32 = (uint32_t)(probe & 0xFFFFFFFF);
            if (lo32 > 0 && lo32 <= 200000) {
                max_length = lo32;
                elem_base = (int32_t *)(items + 0x18);
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
            uintptr_t new_arr = alloc_int32_szarray(items, new_cap);
            g_in_safe_access = 0;
            
            if (!new_arr) continue;
            
            // 拷贝旧元素
            int32_t *new_elem = (int32_t *)(new_arr + 0x20);
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
static char* do_enum_items(int item_type) {
    if (init_il2cpp_context() != 0) return NULL;

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
        int candidates[] = {0x18, 0x28, 0x20, 0x30, -1};
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
    if ((*env)->RegisterNatives(env, menuClass, g_jni_methods, 12) != JNI_OK) {
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

// ========== 主工作线程 ==========
static void *hack_thread(void *arg) {
    int target_gold = (int)(intptr_t)arg;
    LOGI("=== GoldHack started, target_gold=%d ===", target_gold);
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
    for (int i = 0; g_api_table[i].name; i++) {
        if (*g_api_table[i].func_ptr == NULL) {
            LOGE("API %s is NULL, aborting", g_api_table[i].name);
            return NULL;
        }
        LOGI("API ready: %s @ %p", g_api_table[i].name, *g_api_table[i].func_ptr);
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

// ========== .so 入口（constructor）==========
__attribute__((constructor))
void gold_hack_init(void) {
    LOGI("=== libgoldhack.so loaded ===");
    
    pthread_t tid;
    int ret = pthread_create(&tid, NULL, hack_thread, (void*)(intptr_t)TARGET_GOLD);
    if (ret != 0) {
        LOGE("Failed to create hack thread: %d", ret);
    } else {
        pthread_detach(tid);
        LOGI("Hack thread started (target_gold=%d)", TARGET_GOLD);
    }
}
