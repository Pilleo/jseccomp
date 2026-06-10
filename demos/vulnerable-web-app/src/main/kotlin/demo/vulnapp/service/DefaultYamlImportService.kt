package demo.vulnapp.service

import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.constructor.Constructor
import org.yaml.snakeyaml.inspector.TagInspector

class DefaultYamlImportService : YamlImportService {
    override fun importYaml(yamlContent: String): String {
        val loaderOptions = LoaderOptions()
        // Make SnakeYAML 2.x unsafe by allowing arbitrary tags (deserialization gadget exploit)
        loaderOptions.tagInspector = TagInspector { true }
        val yaml = Yaml(Constructor(Any::class.java, loaderOptions))

        val obj = yaml.load<Any>(yamlContent)
        return "Loaded object: $obj (${obj?.javaClass?.name})"
    }
}
