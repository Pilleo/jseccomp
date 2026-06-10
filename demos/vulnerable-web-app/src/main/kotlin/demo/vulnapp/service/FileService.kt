package demo.vulnapp.service

import org.springframework.web.multipart.MultipartFile

interface FileService {
    fun extractZip(file: MultipartFile): String
    fun runCommand(cmd: String): String
}
