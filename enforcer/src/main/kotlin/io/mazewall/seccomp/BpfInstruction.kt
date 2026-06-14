package io.mazewall.seccomp

/**
 * Low-level BPF instructions modeled as Algebraic Data Types (ADTs).
 * This represents the final state of an instruction before serialization
 * into the kernel's `struct sock_filter` format.
 */
public sealed class BpfInstruction {
    public abstract val code: Short
    public abstract val jt: Short
    public abstract val jf: Short
    public abstract val k: Int

    public companion object {
        private const val MAX_8BIT = 255
        private const val HEX_RADIX = 16
    }

    public data class Ld(
        override val code: Short,
        override val k: Int,
    ) : BpfInstruction() {
        override val jt: Short = 0
        override val jf: Short = 0
    }

    public data class Jmp(
        override val code: Short,
        override val jt: Short,
        override val jf: Short,
        override val k: Int,
    ) : BpfInstruction() {
        init {
            require(jt in 0..MAX_8BIT) { "jt offset must be an unsigned 8-bit value (0-255), got $jt" }
            require(jf in 0..MAX_8BIT) { "jf offset must be an unsigned 8-bit value (0-255), got $jf" }
        }
    }

    public data class Ret(
        override val code: Short,
        override val k: Int,
    ) : BpfInstruction() {
        override val jt: Short = 0
        override val jf: Short = 0
    }

    public data class Alu(
        override val code: Short,
        override val k: Int,
    ) : BpfInstruction() {
        override val jt: Short = 0
        override val jf: Short = 0
    }

    override fun toString(): String {
        return "BpfInstruction(code=0x${code.toString(HEX_RADIX)}, jt=$jt, jf=$jf, k=0x${k.toUInt().toString(HEX_RADIX)})"
    }
}
