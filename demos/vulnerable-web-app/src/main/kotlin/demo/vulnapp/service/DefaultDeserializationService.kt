package demo.vulnapp.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream

class DefaultDeserializationService : DeserializationService {
    override fun importJackson(jsonContent: String): String {
        val mapper = ObjectMapper()
        // Insecure configuration allowing arbitrary polymorphic type instantiation
        mapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL
        )
        val obj = mapper.readValue(jsonContent, Any::class.java)
        return "Loaded Jackson object: $obj (${obj?.javaClass?.name})"
    }

    override fun importJava(bytes: ByteArray): String {
        ObjectInputStream(ByteArrayInputStream(bytes)).use { ois ->
            val obj = ois.readObject()
            return "Deserialized Java object: $obj (${obj?.javaClass?.name})"
        }
    }
}
