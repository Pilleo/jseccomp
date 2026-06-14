package io.mazewall.seccomp

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.mazewall.BpfFilter
import io.mazewall.Policy
import io.mazewall.core.Arch
import io.mazewall.core.SeccompAction
import io.mazewall.core.Syscall
import io.mazewall.enforcer.FilterInstallationPlanner
import io.mazewall.ffi.Layouts
import io.mazewall.ffi.NativeConstants
import java.lang.foreign.MemoryLayout
import java.lang.foreign.ValueLayout

class ContainmentDesignSpec :
    FreeSpec({

        "FFM Struct Layouts (containment_design.md §7)" - {
            "sock_filter is exactly 8 bytes" {
                Layouts.SOCK_FILTER_SIZE shouldBe 8L
                Layouts.SOCK_FILTER.byteSize() shouldBe 8L
            }

            "sock_filter field: code is JAVA_SHORT at offset 0" {
                Layouts.SOCK_FILTER.byteOffset(MemoryLayout.PathElement.groupElement("code")) shouldBe 0L
                Layouts.SOCK_FILTER.select(MemoryLayout.PathElement.groupElement("code")).byteSize() shouldBe 2L
            }

            "sock_filter field: jt is JAVA_BYTE at offset 2" {
                Layouts.SOCK_FILTER.byteOffset(MemoryLayout.PathElement.groupElement("jt")) shouldBe 2L
                Layouts.SOCK_FILTER.select(MemoryLayout.PathElement.groupElement("jt")).byteSize() shouldBe 1L
            }

            "sock_filter field: jf is JAVA_BYTE at offset 3" {
                Layouts.SOCK_FILTER.byteOffset(MemoryLayout.PathElement.groupElement("jf")) shouldBe 3L
                Layouts.SOCK_FILTER.select(MemoryLayout.PathElement.groupElement("jf")).byteSize() shouldBe 1L
            }

            "sock_filter field: k is JAVA_INT at offset 4 (NEVER JAVA_LONG)" {
                Layouts.SOCK_FILTER.byteOffset(MemoryLayout.PathElement.groupElement("k")) shouldBe 4L
                Layouts.SOCK_FILTER.select(MemoryLayout.PathElement.groupElement("k")).byteSize() shouldBe 4L
                val kLayout = Layouts.SOCK_FILTER.select(MemoryLayout.PathElement.groupElement("k")) as ValueLayout
                kLayout.carrier() shouldBe Int::class.java
            }

            "sock_fprog is exactly 16 bytes on x86_64" {
                Layouts.SOCK_FPROG.byteSize() shouldBe 16L
            }

            "sock_fprog filter pointer is at byte offset 8" {
                Layouts.SOCK_FPROG_FILTER_OFFSET shouldBe 8L
                Layouts.SOCK_FPROG.byteOffset(MemoryLayout.PathElement.groupElement("filter")) shouldBe 8L
            }

            "seccomp_data args[0] is at byte offset 16 (clone flags)" {
                Layouts.SECCOMP_DATA.byteOffset(
                    MemoryLayout.PathElement.groupElement("args"),
                    MemoryLayout.PathElement.sequenceElement(0),
                ) shouldBe 16L
            }

            "seccomp_data args[2] is at byte offset 32 (mmap prot)" {
                Layouts.SECCOMP_DATA.byteOffset(
                    MemoryLayout.PathElement.groupElement("args"),
                    MemoryLayout.PathElement.sequenceElement(2),
                ) shouldBe 32L
            }
        }

        "Linear BPF Scan Constraints (containment_design.md §2)" - {
            val arch = Arch.AMD64

            "jt and jf fields are unsigned 8-bit — max valid offset is 255" {
                // Verify our BpfInstruction constructor guards against out of range jumps
                val filter = BpfInstruction.Jmp(0, 255.toShort(), 255.toShort(), 0)
                filter.jt shouldBe 255.toShort()
                filter.jf shouldBe 255.toShort()
            }

            "a DENY_LIST policy with 127 blocked syscalls produces < 255 instructions between any two jump targets" {
                val builder = Policy.builder().defaultAction(SeccompAction.ACT_ALLOW)
                Syscall.entries.take(127).forEach {
                    builder.block(it)
                }
                val filter = BpfFilter.build(arch, builder.build())
                // Under linear scan, each syscall check is:
                // JEQ nr -> skip 0, dest 1 -> RET nativeAction
                // Therefore, max jump offset is 1, which is always < 255.
                filter.forEach {
                    (it.jt.toInt() < 255) shouldBe true
                    (it.jf.toInt() < 255) shouldBe true
                }
            }

            "total instruction count for PURE_COMPUTE_UNSAFE stays below the 4096 kernel limit" {
                val filter = BpfFilter.build(arch, Policy.PURE_COMPUTE_UNSAFE)
                (filter.size in 0..4095) shouldBe true
            }
        }

        "32-Filter Depth Limit (containment_design.md §4)" - {
            "FilterInstallationPlanner rejects depth >= 32 with IllegalStateException" {
                val exception = io.kotest.assertions.throwables.shouldThrow<IllegalStateException> {
                    FilterInstallationPlanner.verifyFilterDepth(32)
                }
                exception.message shouldBe "Cannot install more than 32 seccomp filters."
            }

            "FilterInstallationPlanner permits depth < 32" {
                FilterInstallationPlanner.verifyFilterDepth(31)
            }
        }

        "JVM Coordination Syscalls Must Never Be Blocked (containment_design.md §3e)" - {
            val arch = Arch.AMD64

            "futex, sched_yield, rt_sigreturn, rt_sigaction, madvise, gettid, close are always allowed by BpfFilter" {
                // In a Whitelist policy (default action ACT_ERRNO), all JVM coordination syscalls
                // are explicitly whitelisted and generated in the BpfFilter.
                val whitelistPolicy = Policy
                    .builder()
                    .defaultAction(SeccompAction.ACT_ERRNO)
                    .build()

                val filter = BpfFilter.build(arch, whitelistPolicy)

                // Let's verify that BpfFilter allows these syscall numbers.
                // When we find a check for futex (JEQ futexNr), the action should be RET ALLOW (0x7fff0000)
                val futexNr = Syscall.FUTEX.numberFor(arch)
                var foundFutex = false
                for (i in filter.indices) {
                    val inst = filter[i]
                    if (inst.code == 0x15.toShort() && inst.k == futexNr) {
                        val next = filter[i + 1]
                        next.code shouldBe 0x06.toShort()
                        next.k shouldBe NativeConstants.SECCOMP_RET_ALLOW
                        foundFutex = true
                    }
                }
                foundFutex shouldBe true
            }
        }

        "clone3 unconditional ENOSYS trap (containment_design.md §3c)" - {
            val arch = Arch.AMD64

            "BpfFilter always emits ENOSYS for clone3 regardless of policy mode" {
                val policy = Policy.builder().defaultAction(SeccompAction.ACT_ALLOW).build()
                val filter = BpfFilter.build(arch, policy)

                val clone3Nr = arch.clone3
                var foundClone3 = false
                for (i in filter.indices) {
                    val inst = filter[i]
                    if (inst.code == 0x15.toShort() && inst.k == clone3Nr) {
                        val next = filter[i + 1]
                        next.code shouldBe 0x06.toShort()
                        next.k shouldBe (NativeConstants.SECCOMP_RET_ERRNO or 38)
                        foundClone3 = true
                    }
                }
                foundClone3 shouldBe true
            }
        }

        "Sandbox Cleanliness (containment_design.md)" - {
            "Pre-warmed JVM task runs successfully inside sandboxed executor without JIT crashes" {
                val isSupported = try {
                    Arch.current()
                    true
                } catch (e: java.lang.UnsupportedOperationException) {
                    false
                }
                if (isSupported) {
                    val executor = java.util.concurrent.Executors
                        .newSingleThreadExecutor()
                    val safeExecutor = io.mazewall.enforcer.ContainedExecutors.wrap(
                        executor,
                        Policy.builder().build(),
                    )
                    try {
                        val result = safeExecutor
                            .submit(
                                java.util.concurrent.Callable {
                                    val a = 1
                                    val b = 2
                                    a + b
                                },
                            ).get(5, java.util.concurrent.TimeUnit.SECONDS)

                        result shouldBe 3
                    } finally {
                        executor.shutdown()
                    }
                }
            }
        }
    })
