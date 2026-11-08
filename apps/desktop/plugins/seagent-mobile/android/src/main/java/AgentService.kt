package dev.seagent.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import java.io.File

/**
 * Foreground Service that keeps `libseagent.so daemon run` alive (the agent's daemon + App
 * Server on 127.0.0.1:8640). The process is restarted with back-off when it exits — including the
 * planned exit after the setup wizard applies a new configuration.
 */
class AgentService : Service() {
    companion object {
        private const val TAG = "SeagentService"
        private const val CHANNEL = "seagent-agent"
        private const val NOTIFICATION_ID = 8640
        const val ACTION_STOP = "dev.seagent.mobile.STOP"

        fun start(ctx: Context) {
            val i = Intent(ctx, AgentService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, AgentService::class.java).setAction(ACTION_STOP))
        }
    }

    @Volatile private var proc: Process? = null
    @Volatile private var stopping = false
    private var watcher: Thread? = null
    private var multicast: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        goForeground()
        stopping = false
        if (watcher?.isAlive != true) {
            watcher = Thread({ superviseLoop() }, "seagent-supervisor").apply { isDaemon = true; start() }
        }
        return START_STICKY
    }

    private fun goForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "SE Agent", NotificationManager.IMPORTANCE_LOW))
        }
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        val stop = PendingIntent.getService(this, 1, Intent(this, AgentService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this)
        val n = b.setContentTitle("SE Agent is running")
            .setContentText("Console: http://127.0.0.1:8640")
            .setSmallIcon(applicationInfo.icon)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null as android.graphics.drawable.Icon?, "Stop", stop).build())
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    private fun superviseLoop() {
        var backoffMs = 1000L
        while (!stopping) {
            val started = System.currentTimeMillis()
            val code = try {
                val p = launch()
                proc = p
                p.waitFor()
            } catch (e: Exception) {
                Log.e(TAG, "cannot start the agent", e)
                -1
            }
            proc = null
            if (stopping) break
            // A run that lasted a while was healthy: restart quickly (e.g. after the setup wizard).
            backoffMs = if (System.currentTimeMillis() - started > 60_000) 1000L else (backoffMs * 2).coerceAtMost(60_000L)
            Log.w(TAG, "agent exited with $code; restarting in ${backoffMs}ms")
            try { Thread.sleep(backoffMs) } catch (_: InterruptedException) { break }
        }
    }

    private fun launch(): Process {
        AgentRuntime.ensureShare(this)
        val exe = AgentRuntime.exe(this)
        require(exe.isFile) { "missing ${exe.absolutePath} (was the APK built with scripts/prepare-android.sh?)" }
        val home = AgentRuntime.home(this)
        val log = File(home, "daemon.log")
        if (log.length() > 8L * 1024 * 1024) log.renameTo(File(home, "daemon.log.1"))
        if (multicast == null) {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicast = wifi.createMulticastLock("seagent-mdns").apply { setReferenceCounted(false); acquire() }
        }
        val pb = ProcessBuilder(exe.absolutePath, "daemon", "run")
            .directory(home)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
        pb.environment().putAll(AgentRuntime.env(this))
        return pb.start()
    }

    private fun shutdown() {
        stopping = true
        watcher?.interrupt()
        proc?.let { p ->
            // Ask nicely (SIGTERM → graceful daemon stop), then insist.
            p.destroy()
            try { if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly() } catch (_: InterruptedException) {}
        }
        proc = null
        multicast?.let { if (it.isHeld) it.release() }
        multicast = null
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
