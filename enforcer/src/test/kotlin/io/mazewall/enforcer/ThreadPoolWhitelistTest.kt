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
            .defaultAction(SeccompAction.ACT_ERRNO)
            // Notice: no .allowJvmClasspath(), to avoid Landlock errors since ContainedExecutors logic might re-apply it.
            // Wait, we need it to NOT throw ClassFormatError.
            // Why does the JVM try to load ClassFormatError when the task is empty?
            // The execution of `runCatching` inside `wrapRunnable$lambda$0` can trigger `Result` class loading
            // So if we pre-warm `Result` and `ClassFormatError` on the executor FIRST, BEFORE we install any policy...
            .allow(Syscall.READ, Syscall.WRITE)
            .build()

        // Pre-warm the executor thread with no policy installed yet!
        executor
            .submit {
            val ex = java.util.zip.DataFormatException("test")
            val dummy = kotlin.Result.success(1)
            val dummy2 = kotlin.Result.failure<Int>(Exception("warmup"))
            val dummy3 = io.mazewall.Platform.isSupported()
        }.get()

        val wrapped = ContainedExecutors.wrap(executor, policy)

        for (i in 1..35) {
            wrapped
                .submit {
                // Do nothing
            }.get()
        }
        wrapped.shutdown()
    }
}
