package org.xrayrust.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Revoke teardown and always-on/lockdown reporting, without a live [android.net.VpnService]. */
class XrayVpnKillSwitchTest {
    @Test
    fun revokeStopsThenReportsRevoked() {
        val events = mutableListOf<String>()

        handleXrayVpnRevoke(
            stop = { events += "stop" },
            report = { events += it },
        )

        assertEquals(listOf("stop", XRAY_VPN_STOP_REASON_REVOKED), events)
        assertEquals("revoked", XRAY_VPN_STOP_REASON_REVOKED)
    }

    @Test
    fun revokeReportsRevokedEvenWhenStopThrows() {
        val events = mutableListOf<String>()

        val error = assertThrows(IllegalStateException::class.java) {
            handleXrayVpnRevoke(
                stop = {
                    events += "stop"
                    throw IllegalStateException("tun close failed")
                },
                report = { events += it },
            )
        }

        assertEquals("tun close failed", error.message)
        assertEquals(listOf("stop", "revoked"), events)
    }

    @Test
    fun lockdownStatusIsHiddenBeforeApi29() {
        val status = xrayVpnLockdownStatus(
            sdkInt = 28,
            isAlwaysOn = true,
            isLockdownEnabled = true,
        )

        assertNull(status.isAlwaysOn)
        assertNull(status.isLockdownEnabled)
    }

    @Test
    fun lockdownStatusReportsBothTogglesOnApi29() {
        val enabled = xrayVpnLockdownStatus(
            sdkInt = 29,
            isAlwaysOn = true,
            isLockdownEnabled = true,
        )
        val disabled = xrayVpnLockdownStatus(
            sdkInt = 35,
            isAlwaysOn = false,
            isLockdownEnabled = false,
        )

        assertEquals(true as Boolean?, enabled.isAlwaysOn)
        assertEquals(true as Boolean?, enabled.isLockdownEnabled)
        assertEquals(false as Boolean?, disabled.isAlwaysOn)
        assertEquals(false as Boolean?, disabled.isLockdownEnabled)
    }
}
