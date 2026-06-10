package demo.vulnapp.service

import org.apache.logging.log4j.LogManager

class DefaultAdminService : AdminService {
    private val logger = LogManager.getLogger(DefaultAdminService::class.java)

    override fun logMessage(apiVersion: String): String {
        // Log4Shell: direct logging of untrusted user header input using Log4j
        logger.info("Processing admin request. API Version: $apiVersion")
        return "Log processed: $apiVersion"
    }
}
