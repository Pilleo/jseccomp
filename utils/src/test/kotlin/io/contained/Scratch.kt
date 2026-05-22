package io.contained

import io.contained.profiler.Profiler
import java.io.File

object Scratch {
    @JvmStatic
    fun main(args: Array<String>) {
        println("=== Scratch Starting ===")
        if (!Platform.isSupported()) {
            println("Platform not supported!")
            return
        }
        val targetFile = File("/etc/hostname")
        println("Target file exists: ${targetFile.exists()}")
        
        try {
            println("Calling Profiler.profile...")
            val result = Profiler.profile {
                targetFile.readText()
            }
            println("Result: ${result.value}")
            println("Behavior syscalls: ${result.behavior.syscalls}")
            println("Behavior opens: ${result.behavior.opens}")
            println("Behavior stackProfile size: ${result.behavior.stackProfile.size}")
        } catch (t: Throwable) {
            println("Caught exception!")
            t.printStackTrace()
        }
        println("=== Scratch Finished ===")
    }
}
