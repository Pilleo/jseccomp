package demo.vulnapp

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class VulnAppApplicationTests {
    companion object {
        init {
            System.setProperty("org.springframework.boot.logging.LoggingSystem", "none")
        }
    }

    @Test
    fun contextLoads() {
    }
}
