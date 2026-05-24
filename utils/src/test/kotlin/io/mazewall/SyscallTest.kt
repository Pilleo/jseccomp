package io.mazewall

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import kotlin.test.assertEquals

class SyscallTest {
    companion object {
        @JvmStatic
        fun architectures() = listOf(Arch.AMD64, Arch.AARCH64)
    }

    @ParameterizedTest(name = "Checking syscall mappings for {0}")
    @MethodSource("architectures")
    fun `numberFor maps to correct properties`(arch: Arch) {
        assertEquals(arch.fork, Syscall.FORK.numberFor(arch))
        assertEquals(arch.vfork, Syscall.VFORK.numberFor(arch))
        assertEquals(arch.clone, Syscall.CLONE.numberFor(arch))
        assertEquals(arch.clone3, Syscall.CLONE3.numberFor(arch))
        assertEquals(arch.execve, Syscall.EXECVE.numberFor(arch))
        assertEquals(arch.execveat, Syscall.EXECVEAT.numberFor(arch))
        assertEquals(arch.connect, Syscall.CONNECT.numberFor(arch))
        assertEquals(arch.bind, Syscall.BIND.numberFor(arch))
        assertEquals(arch.listen, Syscall.LISTEN.numberFor(arch))
        assertEquals(arch.accept, Syscall.ACCEPT.numberFor(arch))
        assertEquals(arch.accept4, Syscall.ACCEPT4.numberFor(arch))
        assertEquals(arch.sendto, Syscall.SENDTO.numberFor(arch))
        assertEquals(arch.sendmsg, Syscall.SENDMSG.numberFor(arch))
        assertEquals(arch.open, Syscall.OPEN.numberFor(arch))
        assertEquals(arch.openat, Syscall.OPENAT.numberFor(arch))
        assertEquals(arch.openat2, Syscall.OPENAT2.numberFor(arch))
        assertEquals(arch.mmap, Syscall.MMAP.numberFor(arch))
        assertEquals(arch.ptrace, Syscall.PTRACE.numberFor(arch))
        assertEquals(arch.socket, Syscall.SOCKET.numberFor(arch))
        assertEquals(arch.initModule, Syscall.INIT_MODULE.numberFor(arch))
        assertEquals(arch.finitModule, Syscall.FINIT_MODULE.numberFor(arch))
        assertEquals(arch.memfdCreate, Syscall.MEMFD_CREATE.numberFor(arch))
        assertEquals(arch.ioUringSetup, Syscall.IO_URING_SETUP.numberFor(arch))
        assertEquals(arch.bpf, Syscall.BPF.numberFor(arch))
        assertEquals(arch.processVmWritev, Syscall.PROCESS_VM_WRITEV.numberFor(arch))
        assertEquals(arch.processVmReadv, Syscall.PROCESS_VM_READV.numberFor(arch))
        assertEquals(arch.userfaultfd, Syscall.USERFAULTFD.numberFor(arch))
        assertEquals(arch.unshare, Syscall.UNSHARE.numberFor(arch))
        assertEquals(arch.setns, Syscall.SETNS.numberFor(arch))
        assertEquals(arch.mount, Syscall.MOUNT.numberFor(arch))
        assertEquals(arch.umount2, Syscall.UMOUNT2.numberFor(arch))
        assertEquals(arch.pivotRoot, Syscall.PIVOT_ROOT.numberFor(arch))
        assertEquals(arch.chroot, Syscall.CHROOT.numberFor(arch))
        assertEquals(arch.ioctl, Syscall.IOCTL.numberFor(arch))
        assertEquals(arch.prctl, Syscall.PRCTL.numberFor(arch))
    }

    @Test
    fun `numberFor works for all entries on current arch without throwing`() {
        val currentArch =
            try {
                Arch.current()
            } catch (e: UnsupportedOperationException) {
                return
            }

        for (syscall in Syscall.entries) {
            assertDoesNotThrow {
                syscall.numberFor(currentArch)
            }
        }
    }
}
