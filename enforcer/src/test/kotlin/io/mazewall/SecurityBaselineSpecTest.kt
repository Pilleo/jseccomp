package io.mazewall

import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.mazewall.core.Syscall
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

@DisplayName("Security Baseline Documentation Specs")
class SecurityBaselineSpecTest {
    @Nested
    @DisplayName("Given PURE_COMPUTE preset")
    inner class PureCompute {
        private val policy = Policy.PURE_COMPUTE

        @Test
        @DisplayName("It should block all outbound network communication")
        fun blocksNetwork() {
            policy.isSyscallAllowed(Syscall.CONNECT) shouldBe false
            policy.isSyscallAllowed(Syscall.SENDTO) shouldBe false
        }

        @Test
        @DisplayName("It should block shell execution (execve)")
        fun blocksExec() {
            policy.isSyscallAllowed(Syscall.EXECVE) shouldBe false
            policy.isSyscallAllowed(Syscall.EXECVEAT) shouldBe false
        }

        @Test
        @DisplayName("It should allow JVM Classpath reads to prevent NoClassDefFoundError deadlocks")
        fun allowsClasspath() {
            policy.enforceLandlock shouldBe true
            val javaHome = System.getProperty("java.home")
            if (!javaHome.isNullOrEmpty()) {
                policy.allowedFsReadPaths.shouldContain(javaHome)
            }
        }
    }

    @Nested
    @DisplayName("Given NO_EXEC preset")
    inner class NoExec {
        private val policy = Policy.NO_EXEC

        @Test
        @DisplayName("It should block execution but allow network and filesystem")
        fun blocksExecOnly() {
            policy.isSyscallAllowed(Syscall.EXECVE) shouldBe false
            policy.isSyscallAllowed(Syscall.CONNECT) shouldBe true
            policy.isSyscallAllowed(Syscall.OPEN) shouldBe true
        }

        @Test
        @DisplayName("It should block executable memory allocation (mmap PROT_EXEC) by default")
        fun blocksMmapExec() {
            policy.allowMmapExec shouldBe false
        }
    }
}
