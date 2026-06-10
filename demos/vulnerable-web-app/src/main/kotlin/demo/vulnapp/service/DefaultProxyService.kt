package demo.vulnapp.service

import org.springframework.web.client.RestTemplate

class DefaultProxyService : ProxyService {
    private val restTemplate = RestTemplate()

    override fun fetchUrl(url: String): String {
        return try {
            restTemplate.getForObject(url, String::class.java) ?: "Empty response"
        } catch (e: Exception) {
            "Error fetching URL: ${e.message}"
        }
    }
}
