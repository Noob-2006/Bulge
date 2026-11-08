package dev.seagent.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Setup wizard step 7 ("start automatically") on Android: bring the agent back after a reboot. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val a = intent.action
        if (a != Intent.ACTION_BOOT_COMPLETED && a != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val p = AgentRuntime.prefs(ctx)
        if (p.getBoolean("autostart", false) && p.getString("mode", "") == "local") {
            AgentService.start(ctx)
        }
    }
}
