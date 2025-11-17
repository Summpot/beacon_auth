package io.github.summpot.beaconauth.client

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import io.github.summpot.beaconauth.util.PKCEUtils
import io.github.summpot.beaconauth.util.TranslationHelper
import net.minecraft.Util
import net.minecraft.client.Minecraft
import net.minecraft.client.gui.screens.ConfirmLinkScreen
import net.minecraft.network.chat.Component
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
            val jwt = query?.split("&")
                ?.map { it.split("=") }
                ?.find { it[0] == "jwt" }
                ?.getOrNull(1)

            if (jwt.isNullOrBlank()) {
                logger.error("Received callback without JWT parameter")
                sendHtmlResponse(exchange, 400, generateErrorPage("Missing JWT parameter"))
                loginPhaseCallback?.onAuthError("Missing JWT parameter")
                return
            }

            val verifier = currentCodeVerifier
            if (verifier == null) {
                logger.error("No code verifier found - login flow not initiated properly")
                sendHtmlResponse(exchange, 400, generateErrorPage("Login flow not initiated"))
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
            sendHtmlResponse(exchange, 200, generateSuccessPage())
        } catch (e: Exception) {
            logger.error("Error handling auth callback: ${e.message}", e)
            sendHtmlResponse(exchange, 500, generateErrorPage("Internal error: ${e.message}"))
            loginPhaseCallback?.onAuthError(e.message ?: "Unknown error")
        } finally {
            exchange.close()
        }
    }

    private fun sendHtmlResponse(exchange: HttpExchange, statusCode: Int, htmlContent: String) {
        try {
            val responseBytes = htmlContent.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "text/html; charset=UTF-8")
            exchange.sendResponseHeaders(statusCode, responseBytes.size.toLong())
            exchange.responseBody.use { output -> output.write(responseBytes) }
        } catch (e: Exception) {
            logger.error("Failed to send HTTP response: ${e.message}", e)
        }
    }

    private fun generateSuccessPage(): String {
        val title = getTranslation(TranslationHelper.htmlSuccessTitle())
        val heading = getTranslation(TranslationHelper.htmlSuccessHeading())
        val message = getTranslation(TranslationHelper.htmlSuccessMessage())
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>$title</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }
                    .container {
                        text-align: center;
                        background: white;
                        padding: 3rem;
                        border-radius: 1rem;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    }
                    h1 { color: #4caf50; margin-bottom: 1rem; }
                    p { color: #666; font-size: 1.1rem; }
                    .checkmark {
                        font-size: 4rem;
                        animation: bounce 0.5s;
                    }
                    @keyframes bounce {
                        0%, 100% { transform: scale(1); }
                        50% { transform: scale(1.2); }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="checkmark">✓</div>
                    <h1>$heading</h1>
                    <p>$message</p>
                </div>
            </body>
            </html>
        """.trimIndent()
    }

    private fun generateErrorPage(errorMsg: String): String {
        val title = getTranslation(TranslationHelper.htmlErrorTitle())
        val heading = getTranslation(TranslationHelper.htmlErrorHeading())
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>$title</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    }
                    .container {
                        text-align: center;
                        background: white;
                        padding: 3rem;
                        border-radius: 1rem;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                    }
                    h1 { color: #f44336; margin-bottom: 1rem; }
                    p { color: #666; }
                    .error-icon { font-size: 4rem; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-icon">✗</div>
                    <h1>$heading</h1>
                    <p>$errorMsg</p>
                </div>
            </body>
            </html>
        """.trimIndent()
    }

    private fun getTranslation(key: String): String {
        return try {
            Component.translatable(key).string
        } catch (e: Exception) {
            logger.warn("Failed to get translation for key: $key", e)
            key.substringAfterLast('.')
        }
    }

    /**
     * Attempts to bring the Minecraft window to the foreground.
     * Uses platform-specific methods to focus the game window.
     */
    private fun focusMinecraftWindow() {
        try {
            val minecraft = Minecraft.getInstance()
            minecraft.execute {
                // Request focus on the Minecraft window using GLFW
                val windowHandle = minecraft.window.window
                org.lwjgl.glfw.GLFW.glfwRequestWindowAttention(windowHandle)
                logger.info("Successfully requested focus for Minecraft window")
            }
        } catch (e: Exception) {
            logger.warn("Failed to focus Minecraft window: ${e.message}", e)
        }
    }
}
