package io.github.summpot.beaconauth.client

import net.minecraft.network.Connection
import java.lang.ref.WeakReference

/**
 * Tracks whether the current client connection completed BeaconAuth login-phase verification.
 *
 * When BeaconAuth is used as an alternative authentication mechanism, the server-side UUID and
 * secure-chat session state may not match Mojang's online-mode expectations.
 *
 * To keep multiplayer chat usable, we selectively downgrade outgoing chat to unsigned messages
 * for that connection only (see client-side mixins).
 */
object BeaconAuthClientSession {
	@Volatile private var currentConnectionRef: WeakReference<Connection>? = null
	@Volatile private var beaconAuthAuthenticated: Boolean = false

	@JvmStatic
	fun noteHandshake(connection: Connection) {
		currentConnectionRef = WeakReference(connection)
		beaconAuthAuthenticated = false
	}

	@JvmStatic
	fun markAuthenticated(connection: Connection) {
		currentConnectionRef = WeakReference(connection)
		beaconAuthAuthenticated = true
	}

	@JvmStatic
	fun isBeaconAuthAuthenticatedConnection(): Boolean {
		if (!beaconAuthAuthenticated) {
			return false
		}
		val conn = currentConnectionRef?.get() ?: return false
		return try {
			conn.isConnected
		} catch (_: Throwable) {
			// If the field/method is not available on some mappings, be conservative.
			false
		}
	}
}
