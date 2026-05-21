package io.contained

import java.io.File
import java.lang.foreign.Arena
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

/**
 * High-performance Out-of-Process USER_NOTIF Profiler API.
 */
object Profiler {
    private val logger = Logger.getLogger(Profiler::class.java.name)
    val recentLogs = java.util.concurrent.CopyOnWriteArrayList<String>()

    /**
     * Compiles the currently profiled logs into a live Policy object.
     */
    fun compilePolicy(basePolicy: Policy = Policy.PURE_COMPUTE): Policy {
        return BobCompiler.compile(recentLogs, basePolicy)
    }

    /**
     * Compiles the currently profiled logs into a beautiful copy-pasteable Kotlin DSL string.
     */
    fun compileToDsl(basePolicyName: String = "Policy.PURE_COMPUTE"): String {
        return BobCompiler.compileToDsl(recentLogs, basePolicyName)
    }

    /**
     * Clears all accumulated profiling logs.
     */
    fun clear() {
        recentLogs.clear()
    }

    fun wrap(delegate: ExecutorService, vararg policies: Policy): ExecutorService {
        val policy = Policy.combine(*policies)
        
        // Setup socket path
        val tempDir = File(System.getProperty("user.dir"), "build/tmp")
        tempDir.mkdirs()
        val socketFile = File.createTempFile("jseccomp-profiler-", ".sock", tempDir)
        socketFile.delete() // delete so bind can create it
        val socketPath = socketFile.absolutePath

        // Spawn Daemon
        val javaBin = ProcessHandle.current().info().command().orElse("java")
        val classpath = System.getProperty("java.class.path")
        val pb = ProcessBuilder(javaBin, "-cp", classpath, "io.contained.ProfilerDaemon", socketPath)
        val daemonProcess = pb.start()
        val daemonPid = daemonProcess.pid()

        // Set the daemon process as our allowed ptrace tracer under Yama ptrace_scope = 1
        // PR_SET_PTRACER = 0x59616d61
        LinuxNative.prctl(0x59616d61, daemonPid, 0, 0, 0)

        // Read daemon output and print it to System.out, while also keeping it in recentLogs
        Thread {
            daemonProcess.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    println(line)
                    System.out.flush()
                    recentLogs.add(line)
                }
            }
        }.apply { isDaemon = true }.start()

        // Also stream daemon errorStream to System.err
        Thread {
            daemonProcess.errorStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    System.err.println(line)
                    System.err.flush()
                }
            }
        }.apply { isDaemon = true }.start()

        // Ensure daemon process is cleaned up on JVM exit
        Runtime.getRuntime().addShutdownHook(Thread {
            daemonProcess.destroyForcibly()
        })

        return ProfilerExecutorWrapper(delegate, policy, socketPath, daemonProcess)
    }

    private fun connectWithRetry(socketPath: String, maxRetries: Int = 30, delayMs: Long = 100): Int {
        Arena.ofConfined().use { arena ->
            val addr = arena.allocate(LinuxNative.SOCKADDR_UN_LAYOUT)
            addr.fill(0)
            addr.set(ValueLayout.JAVA_SHORT, 0, 1.toShort()) // AF_UNIX = 1
            
            val pathBytes = socketPath.toByteArray(Charsets.UTF_8)
            if (pathBytes.size >= 108) {
                throw IllegalArgumentException("Unix socket path too long: $socketPath")
            }
            val pathSeg = addr.asSlice(2, 108)
            for (i in pathBytes.indices) {
                pathSeg.set(ValueLayout.JAVA_BYTE, i.toLong(), pathBytes[i])
            }

            var lastErrno = 0
            for (retry in 0 until maxRetries) {
                val fdRes = LinuxNative.socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0)
                if (fdRes.returnValue < 0) {
                    throw IllegalStateException("Failed to create socket: errno=${fdRes.errno}")
                }
                val fd = fdRes.returnValue.toInt()
                val connRes = LinuxNative.connect(fd, addr, 110)
                if (connRes.returnValue == 0L) {
                    return fd
                }
                lastErrno = connRes.errno
                LinuxNative.close(fd)
                
                // If daemon exited, stop retrying
                // Wait a bit
                Thread.sleep(delayMs)
            }
            throw IllegalStateException("Failed to connect to daemon socket at $socketPath after $maxRetries retries. Last errno=$lastErrno")
        }
    }

    private fun sendDescriptor(socketFd: Int, fdToSend: Int): Boolean {
        Arena.ofConfined().use { arena ->
            val dummyByte = arena.allocate(ValueLayout.JAVA_BYTE)
            dummyByte.set(ValueLayout.JAVA_BYTE, 0, 0.toByte())

            val iov = arena.allocate(LinuxNative.IOVEC_LAYOUT)
            iov.set(ValueLayout.ADDRESS, LinuxNative.IOVEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("iov_base")), dummyByte)
            iov.set(ValueLayout.JAVA_LONG, LinuxNative.IOVEC_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("iov_len")), 1L)

            val controlBuf = arena.allocate(24)
            controlBuf.fill(0)
            controlBuf.set(ValueLayout.JAVA_LONG, 0, 20L) // cmsg_len
            controlBuf.set(ValueLayout.JAVA_INT, 8, 1)    // cmsg_level (SOL_SOCKET = 1)
            controlBuf.set(ValueLayout.JAVA_INT, 12, 1)   // cmsg_type (SCM_RIGHTS = 1)
            controlBuf.set(ValueLayout.JAVA_INT, 16, fdToSend)

            val msg = arena.allocate(LinuxNative.MSGHDR_LAYOUT)
            msg.fill(0)
            msg.set(ValueLayout.ADDRESS, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_iov")), iov)
            msg.set(ValueLayout.JAVA_LONG, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_iovlen")), 1L)
            msg.set(ValueLayout.ADDRESS, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_control")), controlBuf)
            msg.set(ValueLayout.JAVA_LONG, LinuxNative.MSGHDR_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("msg_controllen")), 24L)

            val res = LinuxNative.sendmsg(socketFd, msg, 0)
            return res.returnValue >= 0
        }
    }

    internal class ProfilerExecutorWrapper(
        private val delegate: ExecutorService,
        private val policy: Policy,
        private val socketPath: String,
        private val daemonProcess: Process
    ) : ExecutorService by delegate {
        
        private val threadApplied = ThreadLocal.withInitial { false }

        override fun execute(command: Runnable) {
            delegate.execute {
                ensureApplied()
                command.run()
            }
        }

        override fun <T> submit(task: Callable<T>): Future<T> =
            delegate.submit(Callable {
                ensureApplied()
                task.call()
            })

        override fun <T> submit(task: Runnable, result: T): Future<T> =
            delegate.submit({
                ensureApplied()
                task.run()
            }, result)

        override fun submit(task: Runnable): Future<*> =
            delegate.submit {
                ensureApplied()
                task.run()
            }

        private fun ensureApplied() {
            if (Thread.currentThread().isVirtual) {
                throw IllegalStateException("Seccomp profiling is not supported on Loom virtual threads.")
            }
            if (!threadApplied.get()) {
                installProfilingFilter()
                threadApplied.set(true)
            }
        }

        private fun installProfilingFilter() {
            val r1 = LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if (r1.returnValue != 0L) {
                throw IllegalStateException("prctl(PR_SET_NO_NEW_PRIVS) failed with errno ${r1.errno}")
            }

            val arch = Arch.current()
            // Unblock bootstrap syscalls to prevent chicken-and-egg deadlocks during socket connection exfiltration
            val profilingPolicy = Policy.builder()
                .base(policy)
                .unblock(Syscall.SOCKET, Syscall.CONNECT, Syscall.SENDMSG, Syscall.SENDTO)
                .build()
            val filters = BpfFilter.build(arch, profilingPolicy, profilingMode = true)

            Arena.ofConfined().use { arena ->
                val prog = LinuxNative.newSockFProg(arena, filters)

                val r = LinuxNative.syscall(
                    arch.seccompSyscallNumber.toLong(),
                    LinuxNative.SECCOMP_SET_MODE_FILTER.toLong(),
                    LinuxNative.SECCOMP_FILTER_FLAG_NEW_LISTENER.toLong(),
                    prog
                )

                if (r.returnValue < 0) {
                    throw IllegalStateException("Failed to install seccomp profiling listener: errno=${r.errno}")
                }

                val listenerFd = r.returnValue.toInt()

                val socketFd = connectWithRetry(socketPath)
                try {
                    val sent = sendDescriptor(socketFd, listenerFd)
                    if (!sent) {
                        throw IllegalStateException("Failed to send seccomp listener FD to daemon")
                    }
                } finally {
                    LinuxNative.close(socketFd)
                    LinuxNative.close(listenerFd)
                }
            }
        }

        override fun shutdown() {
            delegate.shutdown()
        }

        override fun shutdownNow(): List<Runnable> {
            val tasks = delegate.shutdownNow()
            daemonProcess.destroy()
            return tasks
        }
    }
}
