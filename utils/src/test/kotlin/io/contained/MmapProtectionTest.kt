package io.contained

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.ValueLayout
import java.util.concurrent.Executors
import java.util.concurrent.ExecutionException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MmapProtectionTest {

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `mmap with PROT_EXEC is blocked even if mmap syscall is allowed`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().block(Syscall.PTRACE).build())

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor.submit {
                    val linker = Linker.nativeLinker()
                    val mmap = linker.downcallHandle(
                        linker.defaultLookup().find("mmap").get(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG)
                    )

                    val PROT_READ = 0x1
                    val PROT_WRITE = 0x2
                    val PROT_EXEC = 0x4
                    val MAP_PRIVATE = 0x02
                    val MAP_ANONYMOUS = 0x20

                    // This should be blocked by the seccomp filter's argument inspection
                    val res = mmap.invoke(java.lang.foreign.MemorySegment.NULL, 4096L, PROT_READ or PROT_WRITE or PROT_EXEC, MAP_PRIVATE or MAP_ANONYMOUS, -1, 0L) as java.lang.foreign.MemorySegment
                    
                    // We must check the return value and throw to trigger the wrapper's detection
                    if (res.address() == -1L) {
                        throw java.io.IOException("Operation not permitted")
                    }
                }.get()
            }.let { e ->
                assertTrue(e.cause is ContainmentViolationException, "Expected ContainmentViolationException as cause, but got ${e.cause}")
            }
        } finally {
            executor.shutdown()
        }
    }
}
