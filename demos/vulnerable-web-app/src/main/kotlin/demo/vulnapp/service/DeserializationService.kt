package demo.vulnapp.service

interface DeserializationService {
    fun importJackson(jsonContent: String): String
    fun importJava(bytes: ByteArray): String
}
