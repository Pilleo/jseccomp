plugins {
    kotlin("jvm")
    id("info.solidsoft.pitest")
}

kotlin {
    jvmToolchain(22)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // Force a fresh JVM for every test to ensure seccomp filters don't contaminate the environment
    forkEvery = 1
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.kotest.property)
    testImplementation(libs.kotlinxCoroutines)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}

tasks.withType<Test> {
    testLogging {
        showStandardStreams = true
    }
}

tasks.register<JavaExec>("runScratch") {
    group = "application"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("io.mazewall.Scratch")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

pitest {
    junit5PluginVersion.set("1.2.1")

    // Minimal target set for SbobParser only
    targetClasses.set(setOf("io.mazewall.SbobParser*"))
    targetTests.set(setOf("io.mazewall.SbobParserTest"))

    jvmArgs.set(listOf("--enable-native-access=ALL-UNNAMED"))

    threads.set(1)
}
