package io.mazewall.seccomp

import io.mazewall.SockFilter

public class BpfProgram private constructor(
    public val instructions: Array<SockFilter>,
) {
    public companion object {
        @JvmStatic
        public fun builder(): Builder = Builder()
    }

    public class Builder {
        private val instructions = mutableListOf<SockFilter>()

        public fun loadAbsolute(offset: Int): Builder {
            instructions.add(SockFilter(0x20.toShort(), 0, 0, offset))
            return this
        }

        public fun jumpIfEqual(
            k: Int,
            jt: Short,
            jf: Short,
        ): Builder {
            instructions.add(SockFilter(0x15.toShort(), jt, jf, k))
            return this
        }

        public fun jumpIfEqual(
            k: Int,
            skipCount: Short,
        ): Builder {
            instructions.add(SockFilter(0x15.toShort(), 0, skipCount, k))
            return this
        }

        public fun jumpIfSet(
            k: Int,
            jt: Short,
            jf: Short,
        ): Builder {
            instructions.add(SockFilter(0x45.toShort(), jt, jf, k))
            return this
        }

        public fun and(k: Int): Builder {
            instructions.add(SockFilter(0x54.toShort(), 0, 0, k))
            return this
        }

        public fun ret(action: Int): Builder {
            instructions.add(SockFilter(0x06.toShort(), 0, 0, action))
            return this
        }

        public fun build(): BpfProgram {
            return BpfProgram(instructions.toTypedArray())
        }
    }
}
