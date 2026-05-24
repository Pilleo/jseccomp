package io.mazewall

import org.junit.jupiter.api.extension.ConditionEvaluationResult
import org.junit.jupiter.api.extension.ExecutionCondition
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext

@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@ExtendWith(LinuxSupportedCondition::class)
annotation class EnabledIfLinuxAndSupported

class LinuxSupportedCondition : ExecutionCondition {
    override fun evaluateExecutionCondition(context: ExtensionContext): ConditionEvaluationResult {
        val osName = System.getProperty("os.name")
        return when {
            !osName.equals("Linux", ignoreCase = true) ->
                ConditionEvaluationResult.disabled("Only supported on Linux (current: $osName)")

            !Platform.isSupported() ->
                ConditionEvaluationResult.disabled("Platform/Kernel not supported (Seccomp/Landlock missing)")

            else ->
                ConditionEvaluationResult.enabled("Linux and supported")
        }
    }
}
