plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.withType<Test> {
    testLogging {
        showStandardStreams = true
    }
}
