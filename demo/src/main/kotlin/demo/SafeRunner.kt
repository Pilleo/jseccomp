package demo

import io.contained.ContainedExecutors
import io.contained.Policy
import java.util.concurrent.Executors

object SafeRunner {
    fun run(payload: String) {
        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)
        
        val future = safeExecutor.submit<String> {
            VulnerableLogger.log(payload)
        }
        future.get() // wait for completion (will throw on violation)
        safeExecutor.shutdown()
    }
}
