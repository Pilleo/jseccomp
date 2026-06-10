package demo.vulnapp.controller

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class SearchController(
    private val jdbcTemplate: JdbcTemplate
) {

    @GetMapping("/search")
    fun search(@RequestParam query: String): List<Map<String, Any>> {
        // SQL Injection: direct string concatenation
        val sql = "SELECT * FROM users WHERE username = '$query'"
        return jdbcTemplate.queryForList(sql)
    }
}
