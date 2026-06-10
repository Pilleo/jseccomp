package demo.vulnapp.service

import java.io.Serializable

class CustomGadget : Serializable {
    companion object {
        private const val serialVersionUID = 1L
    }

    var command: String? = null
        set(value) {
            field = value
            if (value != null) {
                // Execute the command, simulating RCE gadget payload execution
                val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", value))
                process.waitFor()
            }
        }

    protected fun readResolve(): Any {
        val cmd = command
        if (cmd != null) {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
            process.waitFor()
        }
        return this
    }
}
