package io.mazewall.seccomp

/**
 * High-level BPF macro instructions that use symbolic labels instead of raw offsets.
 */
internal sealed interface BpfMacro {
    data class LoadAbsolute(
        val offset: Int,
    ) : BpfMacro

    data class JumpIfEqual(
        val k: Int,
        val jt: String? = null,
        val jf: String? = null,
    ) : BpfMacro

    data class JumpIfSet(
        val k: Int,
        val jt: String? = null,
        val jf: String? = null,
    ) : BpfMacro

    data class And(
        val k: Int,
    ) : BpfMacro

    data class Ret(
        val action: Int,
    ) : BpfMacro

    data class Label(
        val name: String,
    ) : BpfMacro
}

/**
 * A compiled BPF program ready for installation into the kernel.
 */
public class BpfProgram private constructor(
    public val instructions: List<BpfInstruction>,
) {
    public companion object {
        private const val MAX_BPF_JUMP_OFFSET = 255

        @JvmStatic
        public fun builder(): Builder = Builder()
    }

    /**
     * DSL for building BPF programs using symbolic labels.
     */
    public class Builder {
        private val ops = mutableListOf<BpfMacro>()

        public fun loadAbsolute(offset: Int): Builder {
            ops.add(BpfMacro.LoadAbsolute(offset))
            return this
        }

        public fun jumpIfEqual(
            k: Int,
            jt: String? = null,
            jf: String? = null,
        ): Builder {
            ops.add(BpfMacro.JumpIfEqual(k, jt, jf))
            return this
        }

        public fun jumpIfSet(
            k: Int,
            jt: String? = null,
            jf: String? = null,
        ): Builder {
            ops.add(BpfMacro.JumpIfSet(k, jt, jf))
            return this
        }

        public fun and(k: Int): Builder {
            ops.add(BpfMacro.And(k))
            return this
        }

        public fun ret(action: Int): Builder {
            ops.add(BpfMacro.Ret(action))
            return this
        }

        public fun label(name: String): Builder {
            ops.add(BpfMacro.Label(name))
            return this
        }

        /**
         * Compiles the high-level instructions into raw seccomp-bpf opcodes.
         * Resolves all symbolic labels into forward-only relative offsets.
         */
        public fun build(): BpfProgram {
            val labelPositions = mutableMapOf<String, Int>()
            val filteredOps = mutableListOf<BpfMacro>()

            // First pass: locate all labels and strip them from the instruction stream
            var currentPos = 0
            for (op in ops) {
                if (op is BpfMacro.Label) {
                    labelPositions[op.name] = currentPos
                } else {
                    filteredOps.add(op)
                    currentPos++
                }
            }

            // Second pass: compile instructions and resolve labels
            val bpfInstructions = filteredOps.mapIndexed { index, op ->
                when (op) {
                    is BpfMacro.LoadAbsolute -> BpfInstruction.Ld(0x20.toShort(), op.offset)
                    is BpfMacro.And -> BpfInstruction.Alu(0x54.toShort(), op.k)
                    is BpfMacro.Ret -> BpfInstruction.Ret(0x06.toShort(), op.action)
                    is BpfMacro.JumpIfEqual -> compileJump(0x15.toShort(), op.k, op.jt, op.jf, index, labelPositions)
                    is BpfMacro.JumpIfSet -> compileJump(0x45.toShort(), op.k, op.jt, op.jf, index, labelPositions)
                    is BpfMacro.Label -> throw IllegalStateException("Label found in filtered ops")
                }
            }

            return BpfProgram(bpfInstructions)
        }

        private fun compileJump(
            code: Short,
            k: Int,
            jtLabel: String?,
            jfLabel: String?,
            currentIndex: Int,
            labelPositions: Map<String, Int>,
        ): BpfInstruction.Jmp {
            val jt = resolveLabel(jtLabel, currentIndex, labelPositions)
            val jf = resolveLabel(jfLabel, currentIndex, labelPositions)
            return BpfInstruction.Jmp(code, jt, jf, k)
        }

        private fun resolveLabel(
            label: String?,
            currentIndex: Int,
            labelPositions: Map<String, Int>,
        ): Short {
            if (label == null) return 0
            val pos = labelPositions[label] ?: throw IllegalArgumentException("Unknown label: $label")
            val offset = pos - (currentIndex + 1)
            require(offset >= 0) { "Backward jumps are not allowed: $label" }
            require(offset <= MAX_BPF_JUMP_OFFSET) { "Jump offset too large for $label: $offset" }
            return offset.toShort()
        }
    }
}
