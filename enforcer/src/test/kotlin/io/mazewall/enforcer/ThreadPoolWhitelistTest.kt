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

        // Actually, just pre-warm everything since allowJvmClasspath still intercepts via BPF and causes issues if not fully warm
        // Or just let's catch ClassFormatError and ignore it if it happens during thread pool destruction, as we are testing exhaustion, not functionality
        executor
            .submit {
            val ex = java.util.zip.DataFormatException("test")
            val dummy = kotlin.Result.success(1)
            val dummy2 = kotlin.Result.failure<Int>(Exception("warmup"))
            ContainedExecutors.installOnCurrentThread(Policy.builder().build())
        }.get()

        val policy = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_ERRNO)
            .allowJvmClasspath()
            .allow(Syscall.READ, Syscall.WRITE)
            .build()
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
