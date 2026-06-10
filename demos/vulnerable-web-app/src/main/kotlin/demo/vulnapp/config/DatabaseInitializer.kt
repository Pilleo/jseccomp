package demo.vulnapp.config

import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate

@Configuration
class DatabaseInitializer {

    @Bean
    fun initDb(jdbcTemplate: JdbcTemplate) = CommandLineRunner {
        jdbcTemplate.execute("DROP TABLE IF EXISTS users")
        jdbcTemplate.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(255), secret VARCHAR(255))")
        jdbcTemplate.execute("INSERT INTO users VALUES (1, 'admin', 'FLAG{MAZEWALL_PROVES_SECURITY}')")
        jdbcTemplate.execute("INSERT INTO users VALUES (2, 'user', 'hello123')")
    }
}
