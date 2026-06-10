package demo.vulnapp.config

import demo.vulnapp.service.*
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
@ConditionalOnProperty(name = ["mazewall.enabled"], havingValue = "false", matchIfMissing = true)
class MazewallDisabledConfig {

    @Bean
    fun adminService(): AdminService = DefaultAdminService()

    @Bean
    fun proxyService(): ProxyService = DefaultProxyService()

    @Bean
    fun xmlImportService(): XmlImportService = DefaultXmlImportService()

    @Bean
    fun yamlImportService(): YamlImportService = DefaultYamlImportService()

    @Bean
    fun fileService(): FileService = DefaultFileService()

    @Bean
    fun deserializationService(): DeserializationService = DefaultDeserializationService()
}
