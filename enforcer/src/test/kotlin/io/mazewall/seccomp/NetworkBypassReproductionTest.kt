package io.mazewall.seccomp

import io.mazewall.EnabledIfLinuxAndSupported
import io.mazewall.LinuxNative
import io.mazewall.Policy
import io.mazewall.enforcer.ContainedExecutors
import io.mazewall.enforcer.ContainmentViolationException
import org.junit.jupiter.api.Test
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import kotlin.test.fail

class NetworkBypassReproductionTest {
    @Test
    @EnabledIfLinuxAndSupported
    @Suppress("ThrowsCount")
    fun `reproduce sendmmsg and recvmmsg bypass under NO_NETWORK`() {
        val executor = Executors.newSingleThreadExecutor()
        // Wrap with NO_NETWORK which should block all networking
        val safeExecutor = ContainedExecutors.wrap(executor, Policy.NO_NETWORK)

        try {
            safeExecutor
                .submit {
                // Determine arch-specific syscall numbers for sendmmsg and recvmmsg
                val osArch = System.getProperty("os.arch")
                val isAarch64 = osArch == "aarch64" || osArch == "arm64"
                val sendmmsgNr = if (isAarch64) 269L else 307L
                val recvmmsgNr = if (isAarch64) 268L else 299L

                // Attempt sendmmsg (even with invalid args, seccomp EPERM should trigger first before kernel EINVAL/EBADF)
                // If it bypasses seccomp, the kernel will return EBADF (9) or EFAULT (14) because fd=0 is not a socket or args are null
                val sendRes = LinuxNative.syscall(sendmmsgNr, 0, 0, 0, 0)

                if (sendRes.errno != 1) { // 1 is EPERM (seccomp block)
                    throw IllegalStateException("SECURITY BYPASS: sendmmsg reached the kernel! Errno was ${sendRes.errno} instead of EPERM(1)")
                }

                // Attempt recvmmsg
                val recvRes = LinuxNative.syscall(recvmmsgNr, 0, 0, 0, 0, 0)
                if (recvRes.errno != 1) { // 1 is EPERM (seccomp block)
                    throw IllegalStateException("SECURITY BYPASS: recvmmsg reached the kernel! Errno was ${recvRes.errno} instead of EPERM(1)")
                }
            }.get()
        } catch (e: ExecutionException) {
            val cause = e.cause
            if (cause is ContainmentViolationException) {
                // If we get here, it means ContainedExecutors caught the EPERM correctly from our manual syscalls!
                // Wait, ContainedExecutors maps EPERM to ContainmentViolationException for known operations if we used java networking,
                // but direct LinuxNative.syscall doesn't throw, it returns a SyscallResult.
                // If the direct syscall caused a SIGSYS (kill thread), the future would fail.
                // However, our default action is ACT_ERRNO which returns EPERM in the SyscallResult.
                // So the syscall SHOULD return normally with errno=1, and we check that manually above.
                // If a ContainmentViolationException was thrown, it's fine too.
                return
            }
            if (cause is IllegalStateException && cause.message?.contains("SECURITY BYPASS") == true) {
                fail(cause.message)
            }
            throw e
        } finally {
            executor.shutdown()
        }
    }
}
