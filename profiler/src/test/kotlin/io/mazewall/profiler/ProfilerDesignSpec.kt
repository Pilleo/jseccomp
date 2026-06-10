package io.mazewall.profiler

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.mazewall.ffi.Layouts
import io.mazewall.profiler.engine.ACK_BUF_SIZE
import io.mazewall.profiler.engine.ADDR_UN_SIZE
import io.mazewall.profiler.engine.PROTOCOL_ACK_BYTE
import io.mazewall.profiler.engine.SHUTDOWN_COMMAND_BYTE
import io.mazewall.profiler.engine.SOCKADDR_UN_PATH_SIZE
import java.lang.foreign.MemoryLayout
import java.lang.foreign.ValueLayout

class ProfilerDesignSpec :
    FreeSpec({

    "ACK Protocol Constants (profiler_design.md §2 / architectural_map.md §2)" - {
        "PROTOCOL_ACK_BYTE is exactly 0xAC" {
            PROTOCOL_ACK_BYTE shouldBe 0xAC.toByte()
        }

        "SHUTDOWN_COMMAND_BYTE is exactly 0x53 ('S')" {
            SHUTDOWN_COMMAND_BYTE shouldBe 0x53.toByte()
        }

        "ACK byte is a single byte (ACK_BUF_SIZE == 1)" {
            ACK_BUF_SIZE shouldBe 1L
        }
    }

    "Profiler Transport Invariants (profiler_design.md §5 Operational Hazards)" - {
        "SOCKADDR_UN path field is 108 bytes (sun_path POSIX limit)" {
            SOCKADDR_UN_PATH_SIZE shouldBe 108
            val pathElement = Layouts.SOCKADDR_UN.select(MemoryLayout.PathElement.groupElement("sun_path"))
            pathElement.byteSize() shouldBe 108L
        }

        "SOCKADDR_UN total struct is 110 bytes (2-byte family + 108 path)" {
            ADDR_UN_SIZE shouldBe 110
            Layouts.SOCKADDR_UN.byteSize() shouldBe 110L
            Layouts.SOCKADDR_UN.byteOffset(MemoryLayout.PathElement.groupElement("sun_family")) shouldBe 0L
            val familyLayout = Layouts.SOCKADDR_UN.select(MemoryLayout.PathElement.groupElement("sun_family")) as ValueLayout
            familyLayout.carrier() shouldBe Short::class.java
            Layouts.SOCKADDR_UN.byteOffset(MemoryLayout.PathElement.groupElement("sun_path")) shouldBe 2L
        }
    }
})
