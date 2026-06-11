plugins {
    kotlin("jvm")
    application
}
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}
kotlin {
    jvmToolchain(25)
}
application {
    mainClass.set("demo.DemoAppKt")
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED")
}

dependencies {
    implementation(project(":enforcer"))
    implementation(project(":profiler"))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(kotlin("test"))
}

tasks.withType<Test> {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    testLogging {
        showStandardStreams = true
    }
}
