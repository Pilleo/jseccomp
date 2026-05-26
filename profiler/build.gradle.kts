plugins {
    kotlin("jvm")
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
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.1")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
}

tasks.withType<Test> {
    testLogging {
        showStandardStreams = true
    }
}
