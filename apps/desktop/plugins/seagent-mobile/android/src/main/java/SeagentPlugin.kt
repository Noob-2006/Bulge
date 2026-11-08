package dev.seagent.mobile

import android.app.Activity
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.app.ActivityCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

@InvokeArg
class DiscoverArgs {
    var timeoutMs: Long = 3000
}

@InvokeArg
class AutostartArgs {
    var enabled: Boolean = false
}

/** Called from the app's Rust code (`tauri-plugin-seagent-mobile`), never from page JS. */
@TauriPlugin
class SeagentPlugin(private val activity: Activity) : Plugin(activity) {
    private val ctx: Context get() = activity.applicationContext

    @Command
    fun info(invoke: Invoke) {
        val env = JSObject()
        for ((k, v) in AgentRuntime.env(ctx)) env.put(k, v)
        val ret = JSObject()
        ret.put("exe", AgentRuntime.exe(ctx).absolutePath)
        ret.put("env", env)
        invoke.resolve(ret)
    }

    @Command
    fun startAgent(invoke: Invoke) {
        AgentRuntime.ensureShare(ctx)
        AgentRuntime.prefs(ctx).edit().putString("mode", "local").apply()
        if (!AgentRuntime.hasNotificationPermission(ctx) && Build.VERSION.SDK_INT >= 33) {
            // Without it the service still runs; only its notification is hidden.
            ActivityCompat.requestPermissions(activity, arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 8640)
        }
        AgentService.start(ctx)
        invoke.resolve()
    }

    @Command
    fun stopAgent(invoke: Invoke) {
        AgentService.stop(ctx)
        invoke.resolve()
    }

    @Command
    fun setAutostart(invoke: Invoke) {
        val args = invoke.parseArgs(AutostartArgs::class.java)
        AgentRuntime.prefs(ctx).edit().putBoolean("autostart", args.enabled).apply()
        invoke.resolve()
    }

    @Command
    fun getAutostart(invoke: Invoke) {
        val ret = JSObject()
        ret.put("enabled", AgentRuntime.prefs(ctx).getBoolean("autostart", false))
        invoke.resolve(ret)
    }

    /** DNS-SD browse for `_seagent._tcp` for `timeoutMs`, resolving each service (one at a time:
     *  NsdManager rejects concurrent resolves on older Android versions). */
    @Command
    fun discover(invoke: Invoke) {
        val args = invoke.parseArgs(DiscoverArgs::class.java)
        val nsd = ctx.getSystemService(Context.NSD_SERVICE) as NsdManager
        val wifi = ctx.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val lock = wifi.createMulticastLock("seagent-discover").apply { setReferenceCounted(false); acquire() }
        val found = ConcurrentHashMap<String, JSObject>()
        val queue = ConcurrentLinkedQueue<NsdServiceInfo>()
        val resolving = AtomicBoolean(false)
        val done = AtomicBoolean(false)
        val main = Handler(Looper.getMainLooper())

        fun resolveNext() {
            if (done.get() || !resolving.compareAndSet(false, true)) return
            val next = queue.poll()
            if (next == null) { resolving.set(false); return }
            @Suppress("DEPRECATION")
            nsd.resolveService(next, object : NsdManager.ResolveListener {
                override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                    resolving.set(false); resolveNext()
                }
                override fun onServiceResolved(info: NsdServiceInfo) {
                    val o = JSObject()
                    o.put("name", info.serviceName)
                    @Suppress("DEPRECATION")
                    o.put("host", info.host?.hostAddress ?: "")
                    o.put("port", info.port)
                    val txt = JSObject()
                    for ((k, v) in info.attributes) if (v != null) txt.put(k, String(v, Charsets.UTF_8))
                    o.put("txt", txt)
                    found[info.serviceName] = o
                    resolving.set(false); resolveNext()
                }
            })
        }

        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onServiceLost(info: NsdServiceInfo) { found.remove(info.serviceName) }
            override fun onServiceFound(info: NsdServiceInfo) {
                if (info.serviceType.startsWith("_seagent._tcp")) { queue.add(info); resolveNext() }
            }
        }
        try {
            nsd.discoverServices("_seagent._tcp", NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            lock.release()
            invoke.reject("discovery failed: ${e.message}")
            return
        }
        main.postDelayed({
            done.set(true)
            try { nsd.stopServiceDiscovery(listener) } catch (_: Exception) {}
            if (lock.isHeld) lock.release()
            val hosts = JSArray()
            for (o in found.values) hosts.put(o)
            val ret = JSObject()
            ret.put("hosts", hosts)
            invoke.resolve(ret)
        }, args.timeoutMs.coerceIn(500, 15_000))
    }
}
