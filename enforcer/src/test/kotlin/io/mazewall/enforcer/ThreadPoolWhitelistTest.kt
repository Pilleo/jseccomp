package io.mazewall.enforcer

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.Policy
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

@EnabledIfLinuxAndSupported
class ThreadPoolWhitelistTest {
    @Test
    fun `thread pool whitelist execution exhaustion`() {
        val executor = Executors.newSingleThreadExecutor()

        val policy = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_LOG)
            .allow(Syscall.READ, Syscall.WRITE)
            .build()

        val wrapped = ContainedExecutors.wrap(executor, policy)

        for (i in 1..35) {
            wrapped
                .submit {
                // Do nothing
            }.get()
        }

        // Let's also verify that tightening the whitelist adds a new filter
        val tighterPolicy = Policy
            .builder()
            .defaultAction(SeccompAction.ACT_LOG)
            .allow(Syscall.READ)
            .build()

        val wrapped2 = ContainedExecutors.wrap(wrapped, tighterPolicy)
        wrapped2.submit {}.get()

        wrapped2.shutdown()
    }
}
