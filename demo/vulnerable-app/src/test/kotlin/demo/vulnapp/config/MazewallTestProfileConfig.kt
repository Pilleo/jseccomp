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
 *
 * Uses [Policy.PURE_COMPUTE] + allowMmapExec as the profiling base for all services —
 * the profiler observes what syscalls are actually made rather than enforcing limits.
 */
@TestConfiguration
@ConditionalOnProperty(name = ["mazewall.profile"], havingValue = "true")
class MazewallTestProfileConfig(
    private val profileManager: MazewallProfileManager
) {
    /** Creates a profiling executor and registers it with the manager. */
    private fun wrapForProfiling(): Profiler.ProfilerExecutorWrapper =
        Profiler.wrap(
            Executors.newFixedThreadPool(4),
            Policy.builder().base(Policy.PURE_COMPUTE).allowMmapExec().build()
        ).also { profileManager.register(it) }

    @Bean
    @Primary
    fun adminServiceProfiling(): AdminService {
        val realService = DefaultAdminService()
        val executor = wrapForProfiling()
        return object : AdminService {
            override fun logMessage(apiVersion: String) =
                executor.submit<String> { realService.logMessage(apiVersion) }.get()
        }
    }

    @Bean
    @Primary
    fun proxyServiceProfiling(): ProxyService {
        val realService = DefaultProxyService()
        val executor = wrapForProfiling()
        return object : ProxyService {
            override fun fetchUrl(url: String) =
                executor.submit<String> { realService.fetchUrl(url) }.get()
        }
    }

    @Bean
    @Primary
    fun xmlImportServiceProfiling(): XmlImportService {
        val realService = DefaultXmlImportService()
        val executor = wrapForProfiling()
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
        val executor = wrapForProfiling()
        return object : YamlImportService {
            override fun importYaml(yamlContent: String) =
                executor.submit<String> { realService.importYaml(yamlContent) }.get()
        }
    }

    @Bean
    @Primary
    fun fileServiceProfiling(): FileService {
        val realService = DefaultFileService()
        val executor = wrapForProfiling()
        return object : FileService {
            override fun extractZip(file: org.springframework.web.multipart.MultipartFile) =
                executor.submit<String> { realService.extractZip(file) }.get()
            override fun runCommand(cmd: String) =
                executor.submit<String> { realService.runCommand(cmd) }.get()
        }
    }

    @Bean
    @Primary
    fun deserializationServiceProfiling(): DeserializationService {
        val realService = DefaultDeserializationService()
        val executor = wrapForProfiling()
        return object : DeserializationService {
            override fun importJackson(jsonContent: String) =
                executor.submit<String> { realService.importJackson(jsonContent) }.get()
            override fun importJava(bytes: ByteArray) =
                executor.submit<String> { realService.importJava(bytes) }.get()
        }
    }
}
