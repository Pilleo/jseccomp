package io.mazewall

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ArchTest {

    companion object {
        @JvmStatic
        fun architectures() = listOf(Arch.AMD64, Arch.AARCH64)
    }

    @Test
    fun testCurrentPlatformIsDetected() {
        val osArch = System.getProperty("os.arch")
        if (osArch in listOf("amd64", "x86_64", "aarch64", "arm64")) {
            val arch = Arch.current()
            assertNotNull(arch)
            assertTrue(arch.name == "amd64" || arch.name == "aarch64")
        }
    }

    @ParameterizedTest
    @MethodSource("architectures")
    fun `critical security syscalls are available on all architectures`(arch: Arch) {
        assertTrue(Syscall.EXECVE.numberFor(arch) >= 0, "EXECVE missing on ${arch.name}")
        assertTrue(Syscall.EXECVEAT.numberFor(arch) >= 0, "EXECVEAT missing on ${arch.name}")
        assertTrue(Syscall.MPROTECT.numberFor(arch) >= 0, "MPROTECT missing on ${arch.name}")
        assertTrue(Syscall.MMAP.numberFor(arch) >= 0, "MMAP missing on ${arch.name}")
        assertTrue(Syscall.CLONE.numberFor(arch) >= 0, "CLONE missing on ${arch.name}")
        assertTrue(Syscall.PRCTL.numberFor(arch) >= 0, "PRCTL missing on ${arch.name}")
    }

    @Test
    fun `amd64 has memfd_create syscall number 319`() {
        assertEquals(319, Arch.AMD64.memfdCreate)
    }

    @Test
    fun `aarch64 has memfd_create syscall number 279`() {
        assertEquals(279, Arch.AARCH64.memfdCreate)
    }

    @ParameterizedTest
    @MethodSource("architectures")
    fun `test Arch audit identifiers`(arch: Arch) {
        assertTrue(arch.audit != 0)
        if (arch == Arch.AMD64) {
            assertEquals(0xC000003E.toInt(), arch.audit)
        } else {
            assertEquals(0xC00000B7.toInt(), arch.audit)
        }
    }

    @Test
    fun `test Arch companion access`() {
        val comp = Arch.Companion
        assertNotNull(comp.AMD64)
        assertNotNull(comp.AARCH64)

        val current = Arch.current()
        assertNotNull(current)
    }

    @Test
    fun `test Arch current with explicit arguments`() {
        assertEquals(Arch.AARCH64, Arch.current("aarch64"))
        assertFailsWith<UnsupportedOperationException> {
            Arch.current("mips")
        }
    }
}
