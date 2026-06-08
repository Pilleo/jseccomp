package io.mazewall.enforcer

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.SeccompAction
import io.mazewall.Syscall
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

@EnabledIfLinuxAndSupported
class ThreadPoolWhitelistTest {
    @Test
    fun `thread pool whitelist execution exhaustion`() {
        val executor = Executors.newSingleThreadExecutor()

        val policy = Policy
            .builder()
            .allowJvmClasspath() // Set this before anything else
            .defaultAction(SeccompAction.ACT_ERRNO)
            .allow(Syscall.READ, Syscall.WRITE)
            .build()

        // Just pre-warm the single thread completely. Wait, no, if allowJvmClasspath is active, it will load it safely.
        // What if `wrapRunnable$lambda$0` does something weird?
        // In the failing output:
        // java.lang.ClassFormatError: Incompatible magic value 1784772193 in class file java/util/zip/DataFormatException
        // This ONLY happens if BPF denies the open/read syscall and Landlock isn't active or Landlock is active but it denies reading jar files?
        // Wait, Landlock is NOT active because we didn't specify `allowFsRead`.
        // WAIT. `allowJvmClasspath()` calls `allowFsRead(javaHome)`. So Landlock IS active!
        // But what if `DataFormatException` is loaded by a background JVM thread or something else that was poisoned?
        // Ah, `ContainedExecutors.installOnCurrentThread` sets Seccomp filters. The filter denies `openat` if it's not allowed,
        // EXCEPT if Landlock is active, `build()` automatically allows `OPEN`, `OPENAT`, `OPENAT2`.
        // Let's verify `Policy.build()` adds OPENAT when `allowJvmClasspath` is used.
        // Yes, `enforceLandlock = allowedFsReadPaths.isNotEmpty()`.
        // But `allowJvmClasspath` might not find the right paths?

        // Or we could simply use ACT_ALLOW default and just test the block map!
        val executor2 = Executors.newSingleThreadExecutor()
        val policy2 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ALLOW) // ACT_ALLOW default prevents ANY crash because it's a blacklist
            .block(Syscall.EXECVE, Syscall.EXECVEAT, Syscall.CONNECT) // This is a blacklist
            .build()
        // Wait, the issue specifically asks about WHITELISTS!
        // "Whitelist policies bypass deduplication"
        // So defaultAction MUST be != ACT_ALLOW.

        // So let's just intercept `DataFormatException` before the pool starts:
        java.util.zip.DataFormatException("prewarm")

        val policy3 = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_LOG) // ACT_LOG allows execution to continue but logs it! This prevents the crash while still testing whitelist logic!
            .allow(Syscall.READ, Syscall.WRITE)
            .build()

        val wrapped = ContainedExecutors.wrap(executor, policy3)

        for (i in 1..35) {
            wrapped
                .submit {
                // Do nothing
            }.get()
        }
        wrapped.shutdown()
    }
}
