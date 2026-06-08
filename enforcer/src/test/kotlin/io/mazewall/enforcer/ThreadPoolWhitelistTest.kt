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
