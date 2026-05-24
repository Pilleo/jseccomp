package demo

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors

object SafeRunner {
    fun run(payload: String) {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            val future = safeExecutor.submit<String> {
                VulnerableLogger.log(payload)
            }
            future.get()
        } catch (e: ExecutionException) {
            if (e.cause is ContainmentViolationException) {
                throw e.cause as ContainmentViolationException
            }
            throw e
        } finally {
            safeExecutor.shutdown()
            executor.shutdown()
        }
    }
}
