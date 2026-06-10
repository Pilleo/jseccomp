package demo.vulnapp.service

import com.thoughtworks.xstream.XStream
import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory

class DefaultXmlImportService : XmlImportService {
    override fun importXStream(xmlContent: String): String {
        val xstream = XStream()
        // Configure XStream security to allow all classes (simulating vulnerable defaults)
        XStream.setupDefaultSecurity(xstream)
        xstream.allowTypesByWildcard(arrayOf("**"))
        val obj = xstream.fromXML(xmlContent)
        return "Deserialized with XStream: $obj (${obj?.javaClass?.name})"
    }

    override fun importXXE(xmlContent: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        // Vulnerable defaults (XXE enabled by default in Java Standard Library)
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(ByteArrayInputStream(xmlContent.toByteArray()))
        val root = doc.documentElement
        return "Parsed XML. Root tag: ${root.tagName}, content: ${root.textContent.trim()}"
    }
}
