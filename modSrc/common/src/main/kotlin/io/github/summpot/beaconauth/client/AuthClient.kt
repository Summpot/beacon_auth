package io.github.summpot.beaconauth.client

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
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
            minecraft.setScreen(
                ConfirmLinkScreen({ accepted ->
                    minecraft.setScreen(previous)
                    if (accepted) {
                        Util.getPlatform().openUri(loginUrl)
                        onConfirm()
                    } else {
                        onCancel(TranslationHelper.loginCancelled().string)
                    }
                }, loginUrl, true)
            )
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
     * Uses a smart strategy that switches to fullscreen temporarily if needed.
     *
     * IMPORTANT: We avoid glfwFocusWindow() and glfwShowWindow() in windowed mode as these can cause
     * Minecraft to think it has focus and enable mouse capture, even when the browser
     * actually has focus. This would trap the user's cursor.
     *
     * STRATEGY:
     * - In fullscreen mode: Can reliably focus by restoring if minimized
     * - In windowed mode while not focused: Switch to fullscreen, focus, then restore windowed mode
     * - This provides seamless window activation across all scenarios
     */
    private fun focusMinecraftWindow() {
        try {
            val minecraft = Minecraft.getInstance()
            minecraft.execute {
                val windowHandle = minecraft.window.window

                // Check current window state
                val isIconified = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_ICONIFIED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                val isFocused = org.lwjgl.glfw.GLFW.glfwGetWindowAttrib(windowHandle, org.lwjgl.glfw.GLFW.GLFW_FOCUSED) == org.lwjgl.glfw.GLFW.GLFW_TRUE
                val isFullscreen = minecraft.window.isFullscreen

                logger.info("Window state: Minimized=$isIconified, Focused=$isFocused, Fullscreen=$isFullscreen")

                // Restore if minimized
                if (isIconified) {
                    org.lwjgl.glfw.GLFW.glfwRestoreWindow(windowHandle)
                    logger.info("Restored minimized window")
                }

                // If already focused or fullscreen, just request attention
                if (isFocused || isFullscreen) {
                    org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(windowHandle)
                    logger.info("Window is fullscreen or already focused, requested attention")
                    return@execute
                }

                // Windowed mode and not focused: Use fullscreen trick for reliable activation
                logger.info("Windowed mode without focus - switching to fullscreen temporarily")

                // Save current windowed mode state
                val wasWindowed = !isFullscreen

                // Switch to fullscreen (this reliably grabs focus)
                minecraft.window.toggleFullScreen()

                // Schedule restoration back to windowed mode after a short delay
                if (wasWindowed) {
                    // Use a scheduled task to switch back after 100ms
                    Thread {
                        Thread.sleep(100)
                        minecraft.execute {
                            // Switch back to windowed mode
                            if (minecraft.window.isFullscreen) {
                                minecraft.window.toggleFullScreen()
                                logger.info("Restored windowed mode after focus grab")
                            }
                        }
                    }.start()
                }

                // Close pause screen if it's open (so player returns to gameplay)
                val currentScreen = minecraft.screen
                if (currentScreen != null && currentScreen.javaClass.simpleName == "PauseScreen") {
                    minecraft.setScreen(null)
                    logger.info("Closed pause screen to resume gameplay")
                }

                logger.info("Window activation sequence initiated")
            }
        } catch (e: Exception) {
            logger.warn("Failed to focus window: ${e.message}", e)
            // Fallback to basic window attention request
            try {
                val minecraft = Minecraft.getInstance()
                minecraft.execute {
                    org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(minecraft.window.window)
                }
            } catch (fallbackError: Exception) {
                logger.error("Fallback focus also failed: ${fallbackError.message}")
            }
        }
    }
}
