package dev.seagent.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * Where and how the bundled agent runs on this device. The Rust side of the app gets the same
 * values through the plugin's `info` command, so CLI calls (`setup bootstrap`, `setup link`,
 * `app token`) and the daemon in [AgentService] always agree on SEAGENT_HOME.
 *
 * Why `libseagent.so`: since Android 10 an app may not exec files it wrote itself (W^X), but it
 * may exec what the package installer extracted to nativeLibraryDir. The agent executable is
 * therefore shipped in jniLibs/arm64-v8a under a `lib*.so` name, and the app is packaged with
 * `useLegacyPackaging = true` so the file is really extracted (scripts/prepare-android.sh).
 */
object AgentRuntime {
    const val EXE_NAME = "libseagent.so"
    private const val SHARE_ASSET_DIR = "seagent-share"

    fun exe(ctx: Context): File = File(ctx.applicationInfo.nativeLibraryDir, EXE_NAME)

    fun home(ctx: Context): File = File(ctx.filesDir, "seagent").apply { mkdirs() }

    fun shareDir(ctx: Context): File = File(ctx.filesDir, "share")

    fun env(ctx: Context): Map<String, String> {
        val home = home(ctx)
        val tmp = File(ctx.cacheDir, "tmp").apply { mkdirs() }
        return mapOf(
            "SEAGENT_HOME" to home.absolutePath,
            "HOME" to home.absolutePath,
            "TMPDIR" to tmp.absolutePath,
            "SEAGENT_SHARE_DIR" to shareDir(ctx).absolutePath,
            // The daemon's unix socket lives under SEAGENT_HOME (app-private), not /run/user.
            "XDG_RUNTIME_DIR" to "",
        )
    }

    /** Copy `assets/seagent-share/` to `files/share/` once per app version. */
    fun ensureShare(ctx: Context) {
        val dest = shareDir(ctx)
        val marker = File(dest, ".version")
        val version = versionCode(ctx).toString()
        if (marker.isFile && marker.readText() == version) return
        dest.deleteRecursively()
        copyAssets(ctx, SHARE_ASSET_DIR, dest)
        dest.mkdirs()
        marker.writeText(version)
    }

    private fun copyAssets(ctx: Context, path: String, dest: File) {
        val children = ctx.assets.list(path) ?: return
        if (children.isEmpty()) {
            // a file (or an empty directory, which AssetManager cannot tell apart)
            try {
                ctx.assets.open(path).use { input ->
                    dest.parentFile?.mkdirs()
                    dest.outputStream().use { input.copyTo(it) }
                }
            } catch (_: java.io.IOException) {
                dest.mkdirs()
            }
            return
        }
        dest.mkdirs()
        for (c in children) copyAssets(ctx, "$path/$c", File(dest, c))
    }

    @Suppress("DEPRECATION")
    private fun versionCode(ctx: Context): Long {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
    }

    fun prefs(ctx: Context) = ctx.getSharedPreferences("seagent", Context.MODE_PRIVATE)

    fun hasNotificationPermission(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < 33 || ctx.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
}
