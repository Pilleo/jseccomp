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
    implementation(project(":enforcer"))
    implementation(libs.jackson.kotlin)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.kotest.runner)
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

pitest {
    junit5PluginVersion.set("1.2.1")
    targetClasses.set(setOf("io.mazewall.*"))
    jvmArgs.set(listOf("--enable-native-access=ALL-UNNAMED"))
}
