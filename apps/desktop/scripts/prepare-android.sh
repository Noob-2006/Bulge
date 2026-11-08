#!/usr/bin/env bash
# After `cargo tauri android init`: put the agent and its share/ data into the Android build and
# apply the two app-level settings the plugin manifest cannot set by itself.
#
#   apps/desktop/scripts/prepare-android.sh [path/to/seagent-aarch64-linux-android]
#
# Without an argument it builds `seagent` for aarch64-linux-android with the NDK
# ($ANDROID_NDK_HOME or $NDK_HOME, API level $ANDROID_API, default 26).
#
# What it does:
# 1. jniLibs/arm64-v8a/libseagent.so  ← the agent executable. Android only lets an app exec files
#    the package installer extracted to nativeLibraryDir (W^X since Android 10), hence the lib*.so
#    name. It goes into the plugin library module, whose jniLibs merge into the APK.
# 2. assets/seagent-share/            ← share/ (skills, roles, catalogs); AgentRuntime.ensureShare
#    copies it to files/share and points SEAGENT_SHARE_DIR there.
# 3. gen/android/app/build.gradle.kts ← packaging { jniLibs { useLegacyPackaging = true } } so the
#    .so is really extracted to disk (otherwise it stays compressed inside the APK, not exec-able).
# 4. AndroidManifest.xml              ← android:networkSecurityConfig (cleartext to 127.0.0.1 only)
#    and android:extractNativeLibs="true".
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
app="$(cd "$here/.." && pwd)"
root="$(cd "$app/../.." && pwd)"
plugin="$app/plugins/seagent-mobile/android/src/main"
gen="$app/src-tauri/gen/android"
api="${ANDROID_API:-26}"

[[ -d "$gen" ]] || { echo "run 'cargo tauri android init' in apps/desktop first" >&2; exit 1; }

bin="${1:-}"
if [[ -z "$bin" ]]; then
  ndk="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
  [[ -d "$ndk" ]] || { echo "set ANDROID_NDK_HOME (or pass a prebuilt seagent binary)" >&2; exit 1; }
  hosttag="$(ls "$ndk/toolchains/llvm/prebuilt" | head -1)"
  tc="$ndk/toolchains/llvm/prebuilt/$hosttag/bin"
  export CC_aarch64_linux_android="$tc/aarch64-linux-android$api-clang"
  export AR_aarch64_linux_android="$tc/llvm-ar"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
  (cd "$root" && cargo build --release --locked -p seagent --bin seagent --target aarch64-linux-android)
  bin="$root/target/aarch64-linux-android/release/seagent"
fi

mkdir -p "$plugin/jniLibs/arm64-v8a"
install -m 0755 "$bin" "$plugin/jniLibs/arm64-v8a/libseagent.so"

rm -rf "$plugin/assets/seagent-share"
mkdir -p "$plugin/assets"
cp -R "$root/share" "$plugin/assets/seagent-share"

gradle="$gen/app/build.gradle.kts"
if ! grep -q useLegacyPackaging "$gradle"; then
  cat >> "$gradle" <<'EOF'

// SE Agent: libseagent.so is an executable; it must be extracted to nativeLibraryDir.
android {
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
EOF
fi

manifest="$gen/app/src/main/AndroidManifest.xml"
if ! grep -q seagent_network_security "$manifest"; then
  # Add both attributes to the <application ...> start tag.
  python3 - "$manifest" <<'EOF'
import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
s = re.sub(r"<application\b", '<application android:networkSecurityConfig="@xml/seagent_network_security" android:extractNativeLibs="true"', s, count=1)
s = re.sub(r'\s+android:usesCleartextTraffic="[^"]*"', "", s)
open(p, "w", encoding="utf-8").write(s)
EOF
fi
echo "android: libseagent.so ($(du -h "$plugin/jniLibs/arm64-v8a/libseagent.so" | cut -f1)), share/ assets, gradle + manifest patched"
