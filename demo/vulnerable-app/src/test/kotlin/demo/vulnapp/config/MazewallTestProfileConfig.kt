package demo.vulnapp.config

import demo.vulnapp.service.*
import io.mazewall.Policy
import io.mazewall.profiler.Profiler
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import java.util.concurrent.Executors

/**
 * Overrides standard service beans during profiling-enabled integration tests
 * to wrap them with the [io.mazewall.profiler.Profiler] and register them
 * with the [MazewallProfileManager].
 */
@TestConfiguration
@ConditionalOnProperty(name = ["mazewall.profile"], havingValue = "true")
class MazewallTestProfileConfig(
    private val profileManager: MazewallProfileManager
) {
    private fun wrapForProfiling(serviceName: String, realService: Any, basePolicy: Policy) =
        Profiler.wrap(Executors.newFixedThreadPool(4), Policy.builder().base(Policy.PURE_COMPUTE).allowMmapExec().build())
            .also { profileManager.register(it) }

    @Bean
    @Primary
    fun adminServiceProfiling(): AdminService {
        val realService = DefaultAdminService()
        val executor = wrapForProfiling("adminService", realService, Policy.NO_NETWORK)
        return object : AdminService {
            override fun logMessage(apiVersion: String) =
                executor.submit<String> { realService.logMessage(apiVersion) }.get()
        }
    }

    @Bean
    @Primary
    fun proxyServiceProfiling(): ProxyService {
        val realService = DefaultProxyService()
        val executor = wrapForProfiling("proxyService", realService, Policy.NO_NETWORK)
        return object : ProxyService {
            override fun fetchUrl(url: String) =
                executor.submit<String> { realService.fetchUrl(url) }.get()
        }
    }

    @Bean
    @Primary
    fun xmlImportServiceProfiling(): XmlImportService {
        val realService = DefaultXmlImportService()
        val executor = wrapForProfiling("xmlImportService", realService, Policy.NO_NETWORK)
        return object : XmlImportService {
            override fun importXStream(xmlContent: String) =
                executor.submit<String> { realService.importXStream(xmlContent) }.get()
            override fun importXXE(xmlContent: String) =
                executor.submit<String> { realService.importXXE(xmlContent) }.get()
        }
    }

    @Bean
    @Primary
    fun yamlImportServiceProfiling(): YamlImportService {
        val realService = DefaultYamlImportService()
        val executor = wrapForProfiling("yamlImportService", realService, Policy.NO_NETWORK)
        return object : YamlImportService {
            override fun importYaml(yamlContent: String) =
                executor.submit<String> { realService.importYaml(yamlContent) }.get()
        }
    }

    @Bean
    @Primary
    fun fileServiceProfiling(): FileService {
        val realService = DefaultFileService()
        val executor = wrapForProfiling("fileService", realService, Policy.NO_EXEC)
        return object : FileService {
            override fun extractZip(file: org.springframework.web.multipart.MultipartFile) =
                executor.submit<String> { realService.extractZip(file) }.get()
            override fun runCommand(cmd: String) =
                executor.submit<String> { realService.runCommand(cmd) }.get()
        }
    }
}
