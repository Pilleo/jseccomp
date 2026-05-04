package io.contained

import java.lang.foreign.Arena

/**
 * Handles the installation of seccomp filters onto the current thread.
 */
object SeccompInstaller {
    
    /**
     * Installs the given [policy] onto the calling thread.
     * 
     * This follows a strict sequence:
     * 1. Set PR_SET_NO_NEW_PRIVS (required to use seccomp without root)
     * 2. Verify no_new_privs is active
     * 3. Build the BPF filter for the current architecture
     * 4. Try the modern `seccomp(2)` syscall with TSYNC (synchronizes all threads if possible, but we just use it for robust installation)
     * 5. Fallback to older `prctl(PR_SET_SECCOMP)` if `seccomp(2)` is unavailable
     * 6. Verify the filter is active via `prctl(PR_GET_SECCOMP)`
     */
    fun install(policy: Policy) {
        // Step 1: Set no_new_privs
        val r1 = LinuxNative.prctl(LinuxNative.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if (r1.returnValue != 0) {
            throw IllegalStateException("prctl(PR_SET_NO_NEW_PRIVS) failed: ${LinuxNative.strerror(r1.errno)}")
        }

        // Step 2: Verify no_new_privs is set
        val r2 = LinuxNative.prctl(LinuxNative.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        if (r2.returnValue != 1) {
            throw IllegalStateException("no_new_privs did not take effect")
        }

        // Step 3: Build filter
        val arch = Arch.current()
        val filters = BpfFilter.build(arch, policy)

        Arena.ofConfined().use { arena ->
            val prog = LinuxNative.newSockFProg(arena, filters)

            // Step 4: Try seccomp(2) syscall first (preferred modern path)
            val r3 = LinuxNative.syscall(
                arch.seccompSyscallNumber.toLong(),
                LinuxNative.SECCOMP_SET_MODE_FILTER.toLong(),
                LinuxNative.SECCOMP_FILTER_FLAG_TSYNC.toLong(),
                prog
            )

            if (r3.returnValue != 0) {
                // Step 5: Fall back to prctl for older kernels
                val errno1 = r3.errno
                val r4 = LinuxNative.prctl(
                    LinuxNative.PR_SET_SECCOMP,
                    LinuxNative.SECCOMP_MODE_FILTER.toLong(),
                    prog,
                    0, 0
                )
                if (r4.returnValue != 0) {
                    throw IllegalStateException(
                        "Both seccomp(2) and prctl(PR_SET_SECCOMP) failed. " +
                        "seccomp errno=${LinuxNative.strerror(errno1)}, " +
                        "prctl errno=${LinuxNative.strerror(r4.errno)}"
                    )
                }
            }
        }

        // Step 6: Verify filter is actually installed
        val r5 = LinuxNative.prctl(LinuxNative.PR_GET_SECCOMP, 0, 0, 0, 0)
        if (r5.returnValue != 2) {
            throw IllegalStateException(
                "Seccomp filter verification failed: expected mode 2, got ${r5.returnValue}"
            )
        }
    }
}
