package io.mazewall.seccomp
import io.mazewall.Policy
import io.mazewall.Compiled
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SeccompEngineTest {
    @Test
    fun `default installOnProcess throws UnsupportedOperationException`() {
        val dummyEngine = object : SeccompEngine {
            override fun install(policy: Policy<*, Compiled>) {
                // No-op
            }

            override val isSupported: Boolean
                get() = true
        }

        val emptyPolicy = Policy.builder().build()
        val arch = io.mazewall.core.Arch
            .current()
        val compiledPolicy = emptyPolicy.compile(arch)

        val exception = assertFailsWith<UnsupportedOperationException> {
            dummyEngine.installOnProcess(compiledPolicy)
        }

        assertEquals("Global process containment is not supported by this engine.", exception.message)
    }
}
