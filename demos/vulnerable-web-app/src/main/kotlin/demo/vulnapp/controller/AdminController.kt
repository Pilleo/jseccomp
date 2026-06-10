package demo.vulnapp.controller

import demo.vulnapp.service.AdminService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController

@RestController
class AdminController(
    private val adminService: AdminService
) {
    @GetMapping("/admin/log")
    fun logMessage(
        @RequestHeader(value = "X-Api-Version", required = false, defaultValue = "1.0") apiVersion: String
    ): String {
        return adminService.logMessage(apiVersion)
    }
}
