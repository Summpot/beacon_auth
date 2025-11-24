package io.github.summpot.beaconauth.client

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import io.github.summpot.beaconauth.config.ServerConfig
import io.github.summpot.beaconauth.util.PKCEUtils
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.Util
import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.ConfirmLinkScreen
import org.slf4j.LoggerFactory
import java.net.BindException
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.jvm.Volatile

/**
 * Client helper responsible for PKCE generation, loopback HTTP server, and
 * bridging OAuth callbacks back into the login-phase negotiation.
 */
object AuthClient {
    private val logger = LoggerFactory.getLogger("BeaconAuth/Client")

    private const val PORT_RANGE_START = 38123
    private const val PORT_RANGE_END = 38133
    private const val CALLBACK_PATH = "/auth-callback"

    data class LoginInitPayload(val codeChallenge: String, val boundPort: Int)

    interface LoginPhaseCallback {
        fun onAuthSuccess(jwt: String, verifier: String)
        fun onAuthError(message: String)
    }

    private var httpServer: HttpServer? = null
    private var boundPort: Int = -1
    private var currentCodeVerifier: String? = null
    @Volatile private var loginPhaseCallback: LoginPhaseCallback? = null
    private val serverReady = AtomicBoolean(false)

    fun init() {
        if (!serverReady.get()) {
            startLocalHttpServer()
        }
    }

    @JvmStatic
    fun prepareLoginPhaseCredentials(): LoginInitPayload {
        startLocalHttpServer()
        val verifier = PKCEUtils.generateCodeVerifier()
        val challenge = PKCEUtils.generateCodeChallenge(verifier)
        currentCodeVerifier = verifier
        logger.info("Generated PKCE challenge for login-phase handshake")
        return LoginInitPayload(challenge, boundPort)
    }

    @JvmStatic
    fun registerLoginPhaseCallback(callback: LoginPhaseCallback?) {
        loginPhaseCallback = callback
    }

    @JvmStatic
    fun showLoginConfirmation(loginUrl: String, onConfirm: () -> Unit, onCancel: (String) -> Unit) {
        val minecraft = Minecraft.getInstance()
        val previous = minecraft.screen
        minecraft.execute {
            minecraft.setScreen(ConfirmLinkScreen({ accepted ->
                minecraft.setScreen(previous)
                if (accepted) {
                    Util.getPlatform().openUri(loginUrl)
                    onConfirm()
                } else {
                    onCancel(TranslationHelper.loginCancelled().string)
                }
            }, loginUrl, true))
        }
    }

    private fun startLocalHttpServer() {
        if (serverReady.get()) {
            return
        }

        synchronized(this) {
            if (serverReady.get()) {
                return
            }

            for (port in PORT_RANGE_START..PORT_RANGE_END) {
                try {
                    logger.info("Attempting to bind HTTP server on port $port...")
                    val server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
                    server.createContext(CALLBACK_PATH, this::handleAuthCallback)
                    server.executor = null
                    server.start()
                    httpServer = server
                    boundPort = port
                    serverReady.set(true)
                    logger.info("✓ HTTP server successfully bound to port $port")
                    return
                } catch (e: BindException) {
                    logger.warn("Port $port is already in use, trying next...")
                } catch (e: Exception) {
                    logger.error("Failed to bind on port $port: ${e.message}", e)
                }
            }

            logger.error("CRITICAL: Failed to bind HTTP server on any port in range $PORT_RANGE_START-$PORT_RANGE_END")
            throw IllegalStateException("BeaconAuth client cannot start loopback server")
        }
    }

    private fun handleAuthCallback(exchange: HttpExchange) {
        try {
            val query = exchange.requestURI.query
            val params = query?.split("&")
                ?.map { it.split("=", limit = 2) }
                ?.filter { it.size == 2 }
                ?.associate { it[0] to java.net.URLDecoder.decode(it[1], "UTF-8") }
                ?: emptyMap()

            val jwt = params["jwt"]
            val profileUrl = params["profile_url"]

            if (jwt.isNullOrBlank()) {
                logger.error("Received callback without JWT parameter")
                val redirectUrl = if (profileUrl != null) {
                    "$profileUrl?status=error&message=Missing+JWT+parameter"
                } else {
                    "/profile?status=error&message=Missing+JWT+parameter"
                }
                sendRedirectResponse(exchange, redirectUrl)
                loginPhaseCallback?.onAuthError("Missing JWT parameter")
                return
            }

            val verifier = currentCodeVerifier
            if (verifier == null) {
                logger.error("No code verifier found - login flow not initiated properly")
                val redirectUrl = if (profileUrl != null) {
                    "$profileUrl?status=error&message=Login+flow+not+initiated"
                } else {
                    "/profile?status=error&message=Login+flow+not+initiated"
                }
                sendRedirectResponse(exchange, redirectUrl)
                loginPhaseCallback?.onAuthError("Login flow not initiated")
                return
            }

            logger.info("Received JWT from browser, notifying server...")
            
            // Try to bring Minecraft window to foreground
            try {
                focusMinecraftWindow()
            } catch (e: Exception) {
                logger.warn("Failed to focus Minecraft window: ${e.message}")
            }
            
            loginPhaseCallback?.onAuthSuccess(jwt, verifier)
            currentCodeVerifier = null
            
            // Redirect to profile page with success status
            val redirectUrl = if (profileUrl != null) {
                "$profileUrl?status=success&message=Authentication+successful"
            } else {
                "/profile?status=success&message=Authentication+successful"
            }
            sendRedirectResponse(exchange, redirectUrl)
        } catch (e: Exception) {
            logger.error("Error handling auth callback: ${e.message}", e)
            val query = exchange.requestURI.query
            val params = query?.split("&")
                ?.map { it.split("=", limit = 2) }
                ?.filter { it.size == 2 }
                ?.associate { it[0] to java.net.URLDecoder.decode(it[1], "UTF-8") }
                ?: emptyMap()
            val profileUrl = params["profile_url"]
            val redirectUrl = if (profileUrl != null) {
                "$profileUrl?status=error&message=" + java.net.URLEncoder.encode(e.message ?: "Unknown error", "UTF-8")
            } else {
                "/profile?status=error&message=" + java.net.URLEncoder.encode(e.message ?: "Unknown error", "UTF-8")
            }
            sendRedirectResponse(exchange, redirectUrl)
            loginPhaseCallback?.onAuthError(e.message ?: "Unknown error")
        } finally {
            exchange.close()
        }
    }

    private fun sendRedirectResponse(exchange: HttpExchange, location: String) {
        try {
            exchange.responseHeaders.set("Location", location)
            exchange.sendResponseHeaders(302, -1)
        } catch (e: Exception) {
            logger.error("Failed to send redirect response: ${e.message}", e)
        }
    }

    /**
     * Attempts to bring the Minecraft window to the foreground.
     * Uses ONLY safe approaches that won't interfere with input handling.
     * 
     * IMPORTANT: We avoid glfwFocusWindow() and glfwShowWindow() as these can cause
     * Minecraft to think it has focus and enable mouse capture, even when the browser
     * actually has focus. This would trap the user's cursor.
     * 
     * NOTE: Due to OS-level security restrictions (especially on Windows),
     * a window cannot steal focus from another application (like a browser).
     * The best we can do is:
     * - Request window attention (taskbar icon flashing) - this is safe and usually works
     * - Restore the window if minimized - this is also safe
     * 
     * Users will need to manually click on the Minecraft window after authentication.
     */
    private fun focusMinecraftWindow() {
        try {
            val minecraft = Minecraft.getInstance()
            minecraft.execute {
                val windowHandle = minecraft.window.window
                
                // Check current window state
                val isIconified = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_ICONIFIED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                val isFocused = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_FOCUSED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                
                logger.info("Window state before focus attempt - Minimized: $isIconified, Focused: $isFocused")
                
                // Only restore if minimized - this is safe and helpful
                if (isIconified) {
                    org.lwjgl.glfw.GLFW.glfwRestoreWindow(windowHandle)
                    logger.info("Restored minimized window")
                }
                
                // Request window attention (taskbar flashing) - safest approach
                // This will make the taskbar icon flash without stealing focus or affecting input
                org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(windowHandle)
                logger.info("Requested window attention - taskbar should flash, user needs to click window to continue")
                
                // DO NOT call glfwFocusWindow() or glfwShowWindow() - they can cause input capture issues
            }
        } catch (e: Exception) {
            logger.warn("Failed to request window attention: ${e.message}", e)
        }
    }
}
