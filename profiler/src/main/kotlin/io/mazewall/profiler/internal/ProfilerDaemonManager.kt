package io.mazewall.profiler.internal

import io.mazewall.LinuxNative
import io.mazewall.ffi.NativeConstants
import java.io.IOException
import java.lang.foreign.Arena
import java.lang.foreign.ValueLayout
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.logging.Logger

data class DaemonContext(
    val socketPath: String,
    val socketDir: Path,
    val daemonProcess: Process,
    val shutdownHook: Thread,
)

internal object ProfilerDaemonManager {
    private val logger = Logger.getLogger(ProfilerDaemonManager::class.java.name)
    private val daemonLock = Any()
    private var sharedDaemonContext: DaemonContext? = null

    private const val SHUTDOWN_COMMAND_BYTE = 0x53.toByte() // 'S'
    private const val SHUTDOWN_WAIT_MS = 100L

    fun getOrSpawnSharedDaemon(): DaemonContext {
        synchronized(daemonLock) {
            val existing = sharedDaemonContext
            if (existing != null && existing.daemonProcess.isAlive) {
                LinuxNative.prctl(NativeConstants.PR_SET_PTRACER, existing.daemonProcess.pid(), 0, 0, 0)
                return existing
            }
            val newContext = spawnDaemon()
            sharedDaemonContext = newContext
            return newContext
        }
    }

    fun cleanupDaemon(context: DaemonContext) {
        try {
            Runtime.getRuntime().removeShutdownHook(context.shutdownHook)
        } catch (e: IllegalStateException) {
            // Shutdown already in progress - ignore
            logger.log(java.util.logging.Level.FINE, "Shutdown hook removal skipped: shutdown in progress", e)
        } catch (e: SecurityException) {
            logger.log(java.util.logging.Level.WARNING, "Failed to remove shutdown hook", e)
        }
        triggerDaemonShutdown(context.socketPath)
        context.daemonProcess.destroyForcibly()
        try {
            Files.deleteIfExists(context.socketDir.resolve("profiler.sock"))
            Files.deleteIfExists(context.socketDir)
        } catch (e: IOException) {
            logger.log(
                java.util.logging.Level.WARNING,
                "Failed to delete secure socket directory at ${context.socketDir}",
                e,
            )
        }
    }

    private fun spawnDaemon(): DaemonContext {
        // Diagnostic: ensure the daemon class is accessible (provides compile-time safety)
        val daemonClassName = io.mazewall.profiler.engine.ProfilerDaemon::class.java.name

        val perms = PosixFilePermissions.fromString("rwx------")
        val socketDir = Files.createTempDirectory("mazewall-profiler-", PosixFilePermissions.asFileAttribute(perms))
        val socketPath = socketDir.resolve("profiler.sock").toAbsolutePath().toString()

        val javaBin = System.getProperty("java.home") + "/bin/java"
        val classpath = System.getProperty("java.class.path")

        val jvmArgs = java.lang.management.ManagementFactory
            .getRuntimeMXBean()
            .inputArguments
        val jacocoAgent = jvmArgs.find { it.startsWith("-javaagent:") && it.contains("jacoco") }

        val pbArgs = mutableListOf<String>()
        pbArgs.add(javaBin)
        pbArgs.add("--enable-native-access=ALL-UNNAMED")
        if (jacocoAgent != null) {
            pbArgs.add(jacocoAgent)
        }
        pbArgs.add("-cp")
        pbArgs.add(classpath)
        pbArgs.add(daemonClassName)
        pbArgs.add(socketPath)

        logger.info("Spawning ProfilerDaemon: ${pbArgs.joinToString(" ")}")

        val pb = ProcessBuilder(pbArgs)
        val daemonProcess = pb.start()
        val daemonPid = daemonProcess.pid()

        // Give it a tiny bit of time to check for immediate crashes (e.g. ClassNotFoundException)
        @Suppress("MagicNumber")
        Thread.sleep(1000)
        if (!daemonProcess.isAlive) {
            val exitCode = daemonProcess.exitValue()
            val errorOutput = daemonProcess.errorStream.bufferedReader().readText()
            val output = daemonProcess.inputStream.bufferedReader().readText()
            throw IllegalStateException(
                "ProfilerDaemon failed to start (exitCode=$exitCode).\n" +
                    "STDOUT: $output\n" +
                    "STDERR: $errorOutput",
            )
        }

        LinuxNative.prctl(NativeConstants.PR_SET_PTRACER, daemonPid, 0, 0, 0)

        Thread {
            daemonProcess.errorStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    System.err.println("[DAEMON ERR] $line")
                    System.err.flush()
                }
            }
        }.apply {
            isDaemon = true
            name = "profiler-daemon-stderr"
        }.start()

        Thread {
            daemonProcess.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    System.err.println("[DAEMON OUT] $line")
                    System.err.flush()
                }
            }
        }.apply {
            isDaemon = true
            name = "profiler-daemon-stdout"
        }.start()

        val shutdownHook = Thread {
            daemonProcess.destroyForcibly()
        }
        Runtime.getRuntime().addShutdownHook(shutdownHook)

        return DaemonContext(socketPath, socketDir, daemonProcess, shutdownHook)
    }

    private fun triggerDaemonShutdown(socketPath: String) {
        try {
            Arena.ofConfined().use { arena ->
                val fdRes = LinuxNative.socket(ProfilerSocket.AF_UNIX, ProfilerSocket.SOCK_STREAM, 0)
                if (fdRes.returnValue < 0) return
                val fd = fdRes.returnValue.toInt()
                try {
                    val addr = ProfilerSocket.setupSockAddrUn(arena, socketPath)

                    if (LinuxNative.connect(fd, addr, ProfilerSocket.ADDR_UN_SIZE).returnValue == 0L) {
                        val cmd = arena.allocate(1)
                        cmd.set(ValueLayout.JAVA_BYTE, 0L, SHUTDOWN_COMMAND_BYTE)
                        LinuxNative.write(fd, cmd, 1)
                        Thread.sleep(SHUTDOWN_WAIT_MS)
                    }
                } finally {
                    LinuxNative.close(fd)
                }
            }
        } catch (e: InterruptedException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal interrupted (harmless)", e)
            Thread.currentThread().interrupt()
        } catch (e: IllegalArgumentException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        } catch (e: IllegalStateException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        } catch (e: UnsupportedOperationException) {
            logger.log(java.util.logging.Level.FINE, "Daemon shutdown signal failed (harmless)", e)
        }
    }
}
