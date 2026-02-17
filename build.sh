#!/bin/bash
# build.sh - 编译 gold_hack.c 为 Android arm64 .so
# 
# 使用方式:
#   1. 设置 ANDROID_NDK 环境变量指向 NDK 路径
#   2. ./build.sh [gold_value]
#
# 示例:
#   ./build.sh            # 默认 99999 金币
#   ./build.sh 888888     # 自定义金币值
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/gold_hack.c"
OUTPUT="$SCRIPT_DIR/libgoldhack.so"

# 目标金币值（可通过参数传入）
TARGET_GOLD="${1:-99999}"

# ========== 查找 NDK ==========
find_ndk() {
    # 1. 环境变量
    if [ -n "$ANDROID_NDK" ] && [ -d "$ANDROID_NDK" ]; then
        echo "$ANDROID_NDK"
        return
    fi
    if [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ]; then
        echo "$ANDROID_NDK_HOME"
        return
    fi
    if [ -n "$NDK_HOME" ] && [ -d "$NDK_HOME" ]; then
        echo "$NDK_HOME"
        return
    fi

    # 2. 常见路径
    local candidates=(
        "$HOME/Library/Android/sdk/ndk"
        "$HOME/Android/Sdk/ndk"
        "/usr/local/share/android-ndk"
        "/opt/android-ndk"
    )
    for dir in "${candidates[@]}"; do
        if [ -d "$dir" ]; then
            # 取最新版本
            local latest=$(ls -d "$dir"/*/ 2>/dev/null | sort -V | tail -1)
            if [ -n "$latest" ]; then
                echo "${latest%/}"
                return
            fi
        fi
    done

    # 3. 通过 sdkmanager 查找
    if command -v sdkmanager &>/dev/null; then
        local sdk_root=$(dirname $(dirname $(which sdkmanager)))
        if [ -d "$sdk_root/ndk" ]; then
            local latest=$(ls -d "$sdk_root/ndk"/*/ 2>/dev/null | sort -V | tail -1)
            if [ -n "$latest" ]; then
                echo "${latest%/}"
                return
            fi
        fi
    fi

    return 1
}

NDK=$(find_ndk)
if [ -z "$NDK" ]; then
    echo "❌ Android NDK not found!"
    echo ""
    echo "Please install NDK and set ANDROID_NDK environment variable:"
    echo "  export ANDROID_NDK=\$HOME/Library/Android/sdk/ndk/<version>"
    echo ""
    echo "Or install via Android Studio SDK Manager"
    exit 1
fi

echo "📦 Using NDK: $NDK"

# ========== 查找编译器 ==========
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$HOST_OS" in
    darwin) HOST_TAG="darwin-x86_64" ;;
    linux)  HOST_TAG="linux-x86_64" ;;
    *)      echo "❌ Unsupported OS: $HOST_OS"; exit 1 ;;
esac

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"
if [ ! -d "$TOOLCHAIN" ]; then
    echo "❌ Toolchain not found: $TOOLCHAIN"
    exit 1
fi

# 查找合适的 clang (API 21+)
CC=""
for api in 21 24 26 28 29 30 31 33 34 35; do
    candidate="$TOOLCHAIN/bin/aarch64-linux-android${api}-clang"
    if [ -f "$candidate" ]; then
        CC="$candidate"
        echo "🔧 Compiler: aarch64-linux-android${api}-clang"
        break
    fi
done

if [ -z "$CC" ]; then
    # 尝试通用 clang + target 参数
    if [ -f "$TOOLCHAIN/bin/clang" ]; then
        CC="$TOOLCHAIN/bin/clang --target=aarch64-linux-android21"
        echo "🔧 Compiler: clang --target=aarch64-linux-android21"
    else
        echo "❌ No suitable compiler found in $TOOLCHAIN/bin/"
        exit 1
    fi
fi

# ========== 编译 ==========
echo "🔨 Compiling gold_hack.c (target_gold=$TARGET_GOLD) ..."

$CC \
    -shared \
    -fPIC \
    -O2 \
    -DTARGET_GOLD=$TARGET_GOLD \
    -o "$OUTPUT" \
    "$SRC" \
    -lpthread \
    -llog \
    -lc \
    -Wno-pointer-to-int-cast \
    -Wno-int-to-pointer-cast

echo "✅ Built: $OUTPUT"

# 显示文件信息
ls -lh "$OUTPUT"
file "$OUTPUT" 2>/dev/null || true

echo ""
echo "📋 使用方式:"
echo "  1. 推送到设备: adb push $OUTPUT /data/local/tmp/"
echo "  2. 用 inject.py 注入: python3 inject.py"
echo "  3. 或手动 Frida 加载: frida -U -p <PID> -e 'Module.load(\"/data/local/tmp/libgoldhack.so\")'"
