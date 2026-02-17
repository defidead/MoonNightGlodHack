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
static sigjmp_buf g_jmpbuf;
static volatile int g_in_safe_access = 0;

static void sigsegv_handler(int sig) {
    if (g_in_safe_access) {
        siglongjmp(g_jmpbuf, 1);
    }
    // 不在安全访问中，恢复默认行为
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_sigsegv_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigsegv_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

static void uninstall_sigsegv_handler(void) {
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
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

// 步骤1: 扫描所有可读区域，查找 "il2cpp_xxx\0" 字符串
static void scan_api_strings(void) {
    g_string_match_count = 0;

    install_sigsegv_handler();

    int scanned_regions = 0;
    int skipped_segv = 0;
    for (int r = 0; r < g_region_count && g_string_match_count < MAX_API_STRINGS; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable) continue;
        
        size_t size = region->end - region->start;
        if (size < 16 || size > MAX_SCAN_SIZE) continue;

        // 跳过某些不可能包含字符串的区域
        if (strstr(region->path, "/dev/") || strstr(region->path, "dalvik")) continue;
        // 跳过 GPU/DMA/框架相关的大区域以避免崩溃
        if (strstr(region->path, "/dmabuf") || strstr(region->path, "/gpu") ||
            strstr(region->path, "kgsl") || strstr(region->path, "mali")) continue;
        // 跳过超大的匿名区域（>50MB，不太可能包含 API 字符串）
        if (region->path[0] == '\0' && size > 50 * 1024 * 1024) continue;

        scanned_regions++;
        if (scanned_regions % 500 == 0) {
            LOGI("[scan] Progress: scanned %d regions, found %d strings so far",
                 scanned_regions, g_string_match_count);
        }

        for (int api_idx = 0; g_api_table[api_idx].name; api_idx++) {
            const char *api_name = g_api_table[api_idx].name;
            size_t name_len = strlen(api_name) + 1; // 包含 \0

            // 在这个区域中搜索所有出现的 api_name
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

    LOGI("[scan] Scanned %d readable regions, found %d API string occurrences", scanned_regions, g_string_match_count);
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

                        // 验证函数指针指向某个已映射的区域
                        int valid_ptr = 0;
                        for (int c = 0; c < g_region_count; c++) {
                            if (candidate >= g_regions[c].start && candidate < g_regions[c].end) {
                                if (g_regions[c].readable) {
                                    valid_ptr = 1;
                                }
                                break;
                            }
                        }

                        if (valid_ptr) {
                            *g_api_table[api_idx].func_ptr = (void *)candidate;
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

static JNINativeMethod g_jni_methods[] = {
    { "nativeModifyGold",  "(I)Ljava/lang/String;", (void *)jni_modify_gold },
    { "nativeResetSkillCD", "()Ljava/lang/String;",  (void *)jni_reset_skill_cd },
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
    if ((*env)->RegisterNatives(env, menuClass, g_jni_methods, 2) != JNI_OK) {
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

    // 3. 尝试获取 il2cpp API
    LOGI("Attempting to resolve il2cpp APIs...");
    
    // 方法1: 先尝试 dlsym（无保护的情况下）
    if (try_dlsym_apis() == 0) {
        LOGI("All APIs resolved via dlsym");
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
    }

    // 4. 验证所有 API 已就位
    for (int i = 0; g_api_table[i].name; i++) {
        if (*g_api_table[i].func_ptr == NULL) {
            LOGE("API %s is NULL, aborting", g_api_table[i].name);
            return NULL;
        }
        LOGI("API ready: %s @ %p", g_api_table[i].name, *g_api_table[i].func_ptr);
    }

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
