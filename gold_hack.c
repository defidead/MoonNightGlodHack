/*
 * gold_hack.c - 月圆之夜 金币修改器 (native .so)
 *
 * 功能: 注入后自动查找 RoleInfo 实例并修改 curgold 字段
 * 兼容: 不同设备/不同基地址，运行时动态发现 il2cpp API
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
#include <android/log.h>

// ========== 配置 ==========
#ifndef TARGET_GOLD
#define TARGET_GOLD     99999       // 目标金币值，编译时可用 -DTARGET_GOLD=888888 覆盖
#endif
#ifndef WAIT_SECONDS
#define WAIT_SECONDS    15          // 等待游戏加载的秒数，编译时可用 -DWAIT_SECONDS=20 覆盖
#endif
#define MAX_API_STRINGS 300         // 最大 il2cpp API 字符串数
#define MAX_SCAN_SIZE   (200*1024*1024)  // 单个内存区域最大扫描大小

#define LOG_TAG "GoldHack"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

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

        scanned_pair_regions++;

        install_sigsegv_handler();

        // 遍历每个指针大小的对齐位置
        uintptr_t scan_end = region->end - 4 * sizeof(void*); // 留足空间读后续指针
        for (uintptr_t addr = region->start; addr <= scan_end; addr += sizeof(void*)) {
            // 安全读取：如果 SIGSEGV 则跳过整个区域
            g_in_safe_access = 1;
            if (sigsetjmp(g_jmpbuf, 1) != 0) {
                g_in_safe_access = 0;
                LOGW("[scan] SIGSEGV in resolve_apis_from_pairs at region 0x%" PRIxPTR, region->start);
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

                    // 配对结构可能是 {name, func} 或 {name, ???, func}
                    // 尝试多个偏移找函数指针
                    for (int off = 1; off <= 3; off++) {
                        g_in_safe_access = 1;
                        if (sigsetjmp(g_jmpbuf, 1) != 0) {
                            g_in_safe_access = 0;
                            break;
                        }
                        uintptr_t candidate = *(volatile uintptr_t *)(addr + off * sizeof(void*));
                        g_in_safe_access = 0;

                        if (candidate < 0x10000) continue;
                        // 跳过指向字符串自身的指针（val2 == val1 的情况）
                        if (candidate == val1) continue;

                        // 验证函数指针指向 r-x 可执行区域
                        int valid_code = 0;
                        for (int c = 0; c < g_region_count; c++) {
                            if (candidate >= g_regions[c].start && candidate < g_regions[c].end) {
                                if (g_regions[c].readable && g_regions[c].executable) {
                                    valid_code = 1;
                                }
                                break;
                            }
                        }

                        if (valid_code) {
                            *g_api_table[api_idx].func_ptr = (void *)candidate;
                            resolved++;
                            LOGI("[scan] Resolved %s @ 0x%" PRIxPTR " (string @ 0x%" PRIxPTR ", pair @ 0x%" PRIxPTR ", offset +%d)",
                                 g_api_table[api_idx].name, candidate, val1, addr, off);
                            break; // 找到了，不再尝试其他偏移
                        }
                    }
                }
            }

            // 所有 API 都解析完成
            if (resolved >= API_COUNT) goto done;
        }
    }

done:
    uninstall_sigsegv_handler();
    LOGI("[scan] Scanned %d rw- regions for pairs, resolved %d/%d APIs", scanned_pair_regions, resolved, API_COUNT);
    return (resolved >= API_COUNT) ? 0 : -1;
}

// ========== 查找 RoleInfo 实例并修改金币 ==========
static int modify_gold(int target_gold) {
    // 1. 获取 domain 并附加线程
    Il2CppDomain domain = fn_domain_get();
    if (!domain) {
        LOGE("il2cpp_domain_get returned NULL");
        return -1;
    }
    fn_thread_attach(domain);
    LOGI("Attached to il2cpp domain: %p", domain);

    // 2. 找到 Assembly-CSharp.dll
    size_t asm_count = 0;
    Il2CppAssembly *assemblies = fn_domain_get_assemblies(domain, &asm_count);
    if (!assemblies || asm_count == 0) {
        LOGE("No assemblies found");
        return -1;
    }
    LOGI("Found %zu assemblies", asm_count);

    Il2CppImage csharp_image = NULL;
    for (size_t i = 0; i < asm_count; i++) {
        // assemblies 是指针数组
        Il2CppAssembly asm_ptr = ((Il2CppAssembly *)assemblies)[i];
        Il2CppImage img = fn_assembly_get_image(asm_ptr);
        if (!img) continue;
        const char *name = fn_image_get_name(img);
        if (name && strcmp(name, "Assembly-CSharp.dll") == 0) {
            csharp_image = img;
            break;
        }
    }

    if (!csharp_image) {
        LOGE("Assembly-CSharp.dll not found");
        return -1;
    }
    LOGI("Found Assembly-CSharp.dll: %p", csharp_image);

    // 3. 查找 RoleInfo 类
    Il2CppClass roleInfoClass = fn_class_from_name(csharp_image, "", "RoleInfo");
    if (!roleInfoClass) {
        LOGE("RoleInfo class not found");
        return -1;
    }
    LOGI("RoleInfo klass: %p", roleInfoClass);

    // 4. 重新解析 maps（游戏运行时可能有新的内存分配）
    parse_maps();

    // 5. 在堆内存中扫描 RoleInfo 实例
    //    il2cpp 对象布局: [klass_ptr(8)] [monitor(8)] [fields...]
    //    curgold 在 offset 0x2c
    uintptr_t klass_val = (uintptr_t)roleInfoClass;
    int modified_count = 0;
    int scanned_count = 0;

    for (int r = 0; r < g_region_count; r++) {
        MemRegion *region = &g_regions[r];
        if (!region->readable || !region->writable) continue;
        
        size_t size = region->end - region->start;
        if (size < 0x100 || size > MAX_SCAN_SIZE) continue;
        
        // 跳过 .so / /dev/ 映射
        if (strstr(region->path, ".so") || strstr(region->path, "/dev/")) continue;

        uint8_t *base = (uint8_t *)region->start;
        // 确保有足够空间读取 RoleInfo 对象 (至少 0xf4 字节)
        if (size < 0x100) continue;

        for (size_t off = 0; off <= size - 0x100; off += 8) {
            uintptr_t *p = (uintptr_t *)(base + off);
            
            if (*p != klass_val) continue;

            // 候选对象地址
            uintptr_t obj_addr = (uintptr_t)(base + off);
            
            // 验证 monitor 字段 (offset +8): 应该是 0 或有效指针
            uintptr_t monitor = *(uintptr_t *)(obj_addr + 8);
            if (monitor != 0 && monitor < 0x10000) continue;

            // 验证 roleId (offset 0x10): 应该是 0-200
            int32_t roleId = *(int32_t *)(obj_addr + 0x10);
            if (roleId < 0 || roleId > 200) continue;

            // 验证 maxHp (offset 0x14): 应该是 0-99999
            int32_t maxHp = *(int32_t *)(obj_addr + 0x14);
            if (maxHp < 0 || maxHp > 99999) continue;

            // 验证 curHp (offset 0x18): 应该是 0-99999
            int32_t curHp = *(int32_t *)(obj_addr + 0x18);
            if (curHp < 0 || curHp > 99999) continue;

            // 验证 level (offset 0x24): 应该是 0-100
            int32_t level = *(int32_t *)(obj_addr + 0x24);
            if (level < 0 || level > 100) continue;

            // 读取当前金币
            int32_t *gold_ptr = (int32_t *)(obj_addr + 0x2c);
            int32_t old_gold = *gold_ptr;

            scanned_count++;
            LOGI("Found RoleInfo instance @ 0x%" PRIxPTR ": roleId=%d level=%d HP=%d/%d gold=%d",
                 obj_addr, roleId, level, curHp, maxHp, old_gold);

            // 修改金币
            *gold_ptr = target_gold;
            modified_count++;

            LOGI("  => Gold modified: %d -> %d", old_gold, target_gold);
        }
    }

    LOGI("Scan complete: found %d candidates, modified %d instances", scanned_count, modified_count);
    return modified_count;
}

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

    // 5. 修改金币
    LOGI("=== Modifying gold to %d ===", target_gold);
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
