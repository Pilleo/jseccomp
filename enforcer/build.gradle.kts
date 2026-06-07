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
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
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
    targetClasses.set(setOf("io.mazewall.*"))
    jvmArgs.set(listOf("--enable-native-access=ALL-UNNAMED"))
}
