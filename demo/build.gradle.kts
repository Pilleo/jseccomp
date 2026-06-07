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
    implementation(("io.mazewall:enforcer:0.0.1-prealpha-SNAPSHOT"))
    implementation(("io.mazewall:profiler:0.0.1-prealpha-SNAPSHOT"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
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
