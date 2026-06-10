package demo.vulnapp.service

interface XmlImportService {
    fun importXStream(xmlContent: String): String
    fun importXXE(xmlContent: String): String
}
