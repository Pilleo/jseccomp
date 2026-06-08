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
        val expectedMappings = mutableMapOf<Syscall, Int>()
        expectedMappings.putAll(getProcessMappings(arch))
        expectedMappings.putAll(getNetworkMappings(arch))
        expectedMappings.putAll(getFsBasicMappings(arch))
        expectedMappings.putAll(getFsAttrMappings(arch))
        expectedMappings.putAll(getFsOpsMappings(arch))
        expectedMappings.putAll(getMemoryMappings(arch))
        expectedMappings.putAll(getOtherMappings(arch))

        for (syscall in Syscall.entries) {
            val expected = expectedMappings[syscall] ?: throw IllegalStateException("Missing test mapping for $syscall")
            assertEquals(expected, syscall.numberFor(arch), "Mismatch for $syscall on ${arch.name}")
        }
    }

    private fun getProcessMappings(arch: Arch) =
        mapOf(
        Syscall.FORK to arch.fork,
        Syscall.VFORK to arch.vfork,
        Syscall.CLONE to arch.clone,
        Syscall.CLONE3 to arch.clone3,
        Syscall.EXECVE to arch.execve,
        Syscall.EXECVEAT to arch.execveat,
        Syscall.EXIT to arch.exit,
        Syscall.EXIT_GROUP to arch.exit_group,
        Syscall.GETTID to arch.gettid,
        Syscall.GETPID to arch.getpid,
        Syscall.GETPPID to arch.getppid,
        Syscall.GETUID to arch.getuid,
        Syscall.GETEUID to arch.geteuid,
        Syscall.GETGID to arch.getgid,
        Syscall.GETEGID to arch.getegid,
        Syscall.PTRACE to arch.ptrace,
    )

    private fun getNetworkMappings(arch: Arch) =
        mapOf(
        Syscall.CONNECT to arch.connect,
        Syscall.BIND to arch.bind,
        Syscall.LISTEN to arch.listen,
        Syscall.ACCEPT to arch.accept,
        Syscall.ACCEPT4 to arch.accept4,
        Syscall.SENDTO to arch.sendto,
        Syscall.SENDMSG to arch.sendmsg,
        Syscall.SENDMMSG to arch.sendmmsg,
        Syscall.RECVMMSG to arch.recvmmsg,
        Syscall.SOCKET to arch.socket,
    )

    private fun getFsBasicMappings(arch: Arch) =
        mapOf(
        Syscall.OPEN to arch.open,
        Syscall.OPENAT to arch.openat,
        Syscall.OPENAT2 to arch.openat2,
        Syscall.READ to arch.read,
        Syscall.WRITE to arch.write,
        Syscall.CLOSE to arch.close,
        Syscall.FSTAT to arch.fstat,
        Syscall.LSEEK to arch.lseek,
        Syscall.PREAD64 to arch.pread64,
        Syscall.PWRITE64 to arch.pwrite64,
        Syscall.FCNTL to arch.fcntl,
        Syscall.FSYNC to arch.fsync,
        Syscall.FDATASYNC to arch.fdatasync,
    )

    private fun getFsAttrMappings(arch: Arch) =
        mapOf(
        Syscall.TRUNCATE to arch.truncate,
        Syscall.FTRUNCATE to arch.ftruncate,
        Syscall.GETCWD to arch.getcwd,
        Syscall.UMASK to arch.umask,
        Syscall.CHOWN to arch.chown,
        Syscall.LCHOWN to arch.lchown,
        Syscall.FCHOWN to arch.fchown,
        Syscall.FCHOWNAT to arch.fchownat,
        Syscall.UTIME to arch.utime,
        Syscall.UTIMES to arch.utimes,
        Syscall.UTIMENSAT to arch.utimensat,
        Syscall.MKDIR to arch.mkdir,
        Syscall.MKDIRAT to arch.mkdirat,
        Syscall.RMDIR to arch.rmdir,
    )

    private fun getFsOpsMappings(arch: Arch) =
        mapOf(
        Syscall.RENAME to arch.rename,
        Syscall.RENAMEAT to arch.renameat,
        Syscall.RENAMEAT2 to arch.renameat2,
        Syscall.LINK to arch.link,
        Syscall.LINKAT to arch.linkat,
        Syscall.UNLINK to arch.unlink,
        Syscall.UNLINKAT to arch.unlinkat,
        Syscall.SYMLINK to arch.symlink,
        Syscall.SYMLINKAT to arch.symlinkat,
        Syscall.READLINK to arch.readlink,
        Syscall.READLINKAT to arch.readlinkat,
        Syscall.CHMOD to arch.chmod,
        Syscall.FCHMOD to arch.fchmod,
        Syscall.FCHMODAT to arch.fchmodat,
        Syscall.FSTATAT to arch.fstatat,
        Syscall.STATX to arch.statx,
    )

    private fun getMemoryMappings(arch: Arch) =
        mapOf(
        Syscall.MMAP to arch.mmap,
        Syscall.MPROTECT to arch.mprotect,
        Syscall.PKEY_MPROTECT to arch.pkeyMprotect,
        Syscall.MADVISE to arch.madvise,
        Syscall.MUNMAP to arch.munmap,
        Syscall.BRK to arch.brk,
        Syscall.MEMFD_CREATE to arch.memfdCreate,
    )

    private fun getOtherMappings(arch: Arch) =
        mapOf(
        Syscall.IO_URING_SETUP to arch.ioUringSetup,
        Syscall.IO_URING_ENTER to arch.ioUringEnter,
        Syscall.BPF to arch.bpf,
        Syscall.PROCESS_VM_WRITEV to arch.processVmWritev,
        Syscall.PROCESS_VM_READV to arch.processVmReadv,
        Syscall.USERFAULTFD to arch.userfaultfd,
        Syscall.UNSHARE to arch.unshare,
        Syscall.SETNS to arch.setns,
        Syscall.MOUNT to arch.mount,
        Syscall.UMOUNT2 to arch.umount2,
        Syscall.PIVOT_ROOT to arch.pivotRoot,
        Syscall.CHROOT to arch.chroot,
        Syscall.IOCTL to arch.ioctl,
        Syscall.PRCTL to arch.prctl,
        Syscall.RT_SIGACTION to arch.rt_sigaction,
        Syscall.RT_SIGPROCMASK to arch.rt_sigprocmask,
        Syscall.RT_SIGRETURN to arch.rt_sigreturn,
        Syscall.FUTEX to arch.futex,
        Syscall.SCHED_YIELD to arch.sched_yield,
        Syscall.GETRANDOM to arch.getrandom,
        Syscall.CLOCK_GETTIME to arch.clock_gettime,
        Syscall.PAUSE to arch.pause,
        Syscall.NANOSLEEP to arch.nanosleep,
        Syscall.INIT_MODULE to arch.initModule,
        Syscall.FINIT_MODULE to arch.finitModule,
    )

    @Test
    fun `numberFor works for all entries on current arch without throwing`() {
        val currentArch =
            try {
                Arch.current()
            } catch (e: UnsupportedOperationException) {
                println("Skipping test on unsupported arch: ${e.message}")
                return
            }

        for (syscall in Syscall.entries) {
            assertDoesNotThrow {
                syscall.numberFor(currentArch)
            }
        }
    }
}
