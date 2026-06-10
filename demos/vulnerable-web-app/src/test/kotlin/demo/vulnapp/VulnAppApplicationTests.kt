package demo.vulnapp

import demo.vulnapp.config.MazewallTestProfileConfig
import demo.vulnapp.service.FileService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import

@SpringBootTest(properties = ["mazewall.profile=true", "mazewall.enabled=false"])
@Import(MazewallTestProfileConfig::class)
class VulnAppApplicationTests {
    companion object {
        init {
            System.setProperty("org.springframework.boot.logging.LoggingSystem", "none")
        }
    }

    @Autowired(required = false)
    private val fileService: FileService? = null

    @Test
    fun contextLoads() {
    }

    @Test
    fun testProfilingTrigger() {
        if (fileService != null) {
            try {
                fileService.runCommand("echo Hello Profiler")
            } catch (ignored: Exception) {
            }
        }
    }
}
