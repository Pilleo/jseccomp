package demo.vulnapp.controller

import demo.vulnapp.service.XmlImportService
import demo.vulnapp.service.YamlImportService
import demo.vulnapp.service.DeserializationService
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class ImportController(
    private val yamlImportService: YamlImportService,
    private val xmlImportService: XmlImportService,
    private val deserializationService: DeserializationService
) {

    @PostMapping("/import/yaml")
    fun importYaml(@RequestBody body: String): String {
        return yamlImportService.importYaml(body)
    }

    @PostMapping("/import/xstream")
    fun importXStream(@RequestBody body: String): String {
        return xmlImportService.importXStream(body)
    }

    @PostMapping("/import/xxe")
    fun importXXE(@RequestBody body: String): String {
        return xmlImportService.importXXE(body)
    }

    @PostMapping("/import/jackson")
    fun importJackson(@RequestBody body: String): String {
        return deserializationService.importJackson(body)
    }

    @PostMapping("/import/java")
    fun importJava(@RequestBody body: ByteArray): String {
        return deserializationService.importJava(body)
    }

    @org.springframework.web.bind.annotation.GetMapping("/exploit/payload")
    fun getPayload(@org.springframework.web.bind.annotation.RequestParam command: String): ByteArray {
        val gadget = demo.vulnapp.service.CustomGadget()
        val field = demo.vulnapp.service.CustomGadget::class.java.getDeclaredField("command")
        field.isAccessible = true
        field.set(gadget, command)
        
        val baos = java.io.ByteArrayOutputStream()
        java.io.ObjectOutputStream(baos).use { oos ->
            oos.writeObject(gadget)
        }
        return baos.toByteArray()
    }
}
