package demo.vulnapp.config

import demo.vulnapp.service.*
import io.mazewall.Policy
import io.mazewall.SbobParser
import io.mazewall.enforcer.ContainedExecutors
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.multipart.MultipartFile
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import java.util.logging.Logger
import java.nio.file.Files
import java.nio.file.Paths

@Configuration
@ConditionalOnProperty(name = ["mazewall.enabled"], havingValue = "true")
class MazewallConfig {
    private val logger = Logger.getLogger(MazewallConfig::class.java.name)
    private val executors = java.util.concurrent.CopyOnWriteArrayList<ExecutorService>()

    private fun wrapExecutor(delegate: ExecutorService, basePolicy: Policy<*, *>): ExecutorService {
        executors.add(delegate)
        val sbobPath = System.getProperty("mazewall.sbob.path") ?: "/app/sbob.json"
        val bobFile = Paths.get(sbobPath)
        val finalPolicy = if (Files.exists(bobFile)) {
            logger.info("Engaging SBoB ENFORCEMENT mode. Loading ruleset from: $sbobPath")
            SbobParser.parseToPolicy(bobFile, basePolicy)
        } else {
            logger.warning("SBoB file not found at $sbobPath. Falling back to default static policy.")
            basePolicy
        }
        return ContainedExecutors.wrap(delegate, finalPolicy)
    }

    @jakarta.annotation.PreDestroy
    fun onDestroy() {
        logger.info("Spring context shutting down. Terminating Mazewall protected executors...")
        for (executor in executors) {
            try {
                executor.shutdown()
            } catch (e: Exception) {
                // Suppress shutdown exception to avoid interrupting other PreDestroy hooks
            }
        }
    }

    @Bean
    fun adminService(): AdminService {
        val realService = DefaultAdminService()
        val basePolicy = Policy.builder().base(Policy.NO_NETWORK).allowMmapExec().build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : AdminService {
            override fun logMessage(apiVersion: String) =
                executor.submit<String> { realService.logMessage(apiVersion) }.get()
        }
    }

    @Bean
    fun proxyService(): ProxyService {
        val realService = DefaultProxyService()
        val basePolicy = Policy.builder().base(Policy.NO_NETWORK).allowMmapExec().build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : ProxyService {
            override fun fetchUrl(url: String) =
                executor.submit<String> { realService.fetchUrl(url) }.get()
        }
    }

    @Bean
    fun xmlImportService(): XmlImportService {
        val realService = DefaultXmlImportService()
        val basePolicy = Policy.builder()
            .base(Policy.NO_NETWORK)
            .allowMmapExec()
            .allowFsRead("/app/data")
            .allowJvmClasspath()
            .build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : XmlImportService {
            override fun importXStream(xmlContent: String) =
                executor.submit<String> { realService.importXStream(xmlContent) }.get()

            override fun importXXE(xmlContent: String) =
                executor.submit<String> { realService.importXXE(xmlContent) }.get()
        }
    }

    @Bean
    fun yamlImportService(): YamlImportService {
        val realService = DefaultYamlImportService()
        val basePolicy = Policy.builder()
            .base(Policy.NO_NETWORK)
            .allowMmapExec()
            .allowFsRead("/app/data")
            .allowJvmClasspath()
            .build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : YamlImportService {
            override fun importYaml(yamlContent: String) =
                executor.submit<String> { realService.importYaml(yamlContent) }.get()
        }
    }

    @Bean
    fun fileService(): FileService {
        val realService = DefaultFileService()
        val basePolicy = Policy.builder()
            .base(Policy.NO_EXEC)
            .allowMmapExec()
            .allowFsRead("/app/uploads")
            .allowFsWrite("/app/uploads")
            .allowJvmClasspath()
            .build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : FileService {
            override fun extractZip(file: MultipartFile) =
                executor.submit<String> { realService.extractZip(file) }.get()

            override fun runCommand(cmd: String) =
                executor.submit<String> { realService.runCommand(cmd) }.get()
        }
    }

    @Bean
    fun deserializationService(): DeserializationService {
        val realService = DefaultDeserializationService()
        val basePolicy = Policy.builder()
            .base(Policy.PURE_COMPUTE)
            .allowMmapExec()
            .allowFsRead("/app/data")
            .allowJvmClasspath()
            .build()
        val executor = wrapExecutor(Executors.newFixedThreadPool(4), basePolicy)
        return object : DeserializationService {
            override fun importJackson(jsonContent: String) =
                executor.submit<String> { realService.importJackson(jsonContent) }.get()

            override fun importJava(bytes: ByteArray) =
                executor.submit<String> { realService.importJava(bytes) }.get()
        }
    }
}
