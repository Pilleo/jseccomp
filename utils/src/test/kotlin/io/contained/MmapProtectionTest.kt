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

/**
 * Integration tests verifying that [BpfFilter] correctly performs argument inspection on both
 * `mmap` and `mprotect` system calls to prevent dynamic shellcode execution.
 * 
 * Specifically, the BPF filter intercepts these system calls and validates the third argument
 * (`prot` at `args[2]` in `struct seccomp_data`, mapped at offset 32), returning `EPERM` if the
 * `PROT_EXEC` (0x04) bit is set. This protects worker threads from creating executable memory 
 * regions without interfering with JIT compilation running on unrestricted threads.
 */
class MmapProtectionTest {

    /**
     * Verifies that attempting to allocate executable memory directly using `mmap` with the 
     * `PROT_EXEC` flag set causes the kernel to block the call with `EPERM`, which propagates
     * as a [ContainmentViolationException].
     * 
     * The BPF filter performs argument inspection on `mmap` by loading the lower 32 bits of 
     * `args[2]` (offset 32) and checking if `PROT_EXEC` (0x04) is present.
     */
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

    /**
     * Verifies that attempting to mark an existing non-executable memory region as executable
     * using `mprotect` with `PROT_EXEC` causes the kernel to block the call with `EPERM`, which
     * propagates as a [ContainmentViolationException].
     * 
     * The BPF filter performs argument inspection on `mprotect` by loading the lower 32 bits of 
     * `args[2]` (offset 32) and checking if `PROT_EXEC` (0x04) is present.
     */
    @Test
    @EnabledOnOs(OS.LINUX)
    fun `mprotect with PROT_EXEC is blocked even if mprotect syscall is allowed`() {
        if (!Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build()) // Policy that allows mprotect by default but BPF blocks PROT_EXEC

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor.submit {
                    val linker = Linker.nativeLinker()
                    val mmap = linker.downcallHandle(
                        linker.defaultLookup().find("mmap").get(),
                        FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG)
                    )
                    val mprotect = linker.downcallHandle(
                        linker.defaultLookup().find("mprotect").get(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT)
                    )

                    val PROT_READ = 0x1
                    val PROT_WRITE = 0x2
                    val PROT_EXEC = 0x4
                    val MAP_PRIVATE = 0x02
                    val MAP_ANONYMOUS = 0x20

                    // 1. Allocate some RW memory
                    val addr = mmap.invoke(java.lang.foreign.MemorySegment.NULL, 4096L, PROT_READ or PROT_WRITE, MAP_PRIVATE or MAP_ANONYMOUS, -1, 0L) as java.lang.foreign.MemorySegment
                    if (addr.address() == -1L) throw java.io.IOException("mmap failed")

                    // 2. Try to make it executable - this should be blocked
                    val res = mprotect.invoke(addr, 4096L, PROT_READ or PROT_EXEC) as Int
                    
                    if (res == -1) {
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
