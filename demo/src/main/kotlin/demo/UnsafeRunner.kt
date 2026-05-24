package demo

import java.util.concurrent.Executors

object UnsafeRunner {
    fun run(payload: String) {
        val executor = Executors.newSingleThreadExecutor()
        val future =
            executor.submit<String> {
                VulnerableLogger.log(payload)
            }
        future.get() // wait for completion
        executor.shutdown()
    }
}
