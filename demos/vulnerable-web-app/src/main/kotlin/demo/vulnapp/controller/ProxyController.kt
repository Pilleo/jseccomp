package demo.vulnapp.controller

import demo.vulnapp.service.ProxyService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class ProxyController(
    private val proxyService: ProxyService
) {

    @GetMapping("/proxy")
    fun proxy(@RequestParam url: String): String {
        return proxyService.fetchUrl(url)
    }
}
