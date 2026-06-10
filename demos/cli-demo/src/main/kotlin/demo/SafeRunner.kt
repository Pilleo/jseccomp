package demo

import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors

object SafeRunner {
    fun run(payload: String) {
        val executor = Executors.newSingleThreadExecutor()
        try {
            // Wrap inside try so the raw executor is always shut down in finally,
            // even if ContainedExecutors.wrap() itself throws (e.g. seccomp install failure).
            val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
            val future = safeExecutor.submit<String> {
                VulnerableLogger.log(payload)
            }
            future.get()
        } catch (expected: ExecutionException) {
            // We intentionally unwrap the ExecutionException to expose the underlying
            // ContainmentViolationException to the caller for clearer demo output.
            if (expected.cause is ContainmentViolationException) {
                throw expected.cause as ContainmentViolationException
            }
            throw expected
        } finally {
            // The wrapper delegates shutdown to this executor — shutting down once here is sufficient.
            executor.shutdown()
        }
    }
}
