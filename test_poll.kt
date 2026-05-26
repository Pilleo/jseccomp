import java.lang.foreign.*
import java.lang.invoke.*

fun main() {
    val linker = Linker.nativeLinker()
    val stdlib = linker.defaultLookup()
    val pollSym = stdlib.find("poll").get()
    println("poll found: " + pollSym)
}
