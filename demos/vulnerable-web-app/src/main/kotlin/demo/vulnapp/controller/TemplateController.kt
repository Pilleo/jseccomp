package demo.vulnapp.controller

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestHeader

@Controller
class TemplateController {

    @GetMapping("/template")
    fun template(
        @RequestParam(required = false, defaultValue = "hello") lang: String,
        @RequestHeader(value = "X-Lang", required = false) xLang: String?,
        model: Model
    ): String {
        val finalLang = xLang ?: lang
        return "hello :: " + finalLang
    }
}
