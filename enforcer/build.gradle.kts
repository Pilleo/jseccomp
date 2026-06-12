plugins {
    kotlin("jvm")
    id("info.solidsoft.pitest")
}

kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    systemProperty("kotest.framework.classpath.scanning.config.disable", "true")
    exclude("**/seccomp/**")
    exclude("**/landlock/**")
    exclude("**/SecurityPolicyTest*")
    exclude("**/ProcessContainmentInheritanceTest*")
    exclude("**/ContainedExecutorsTest*")
    exclude("**/VirtualThreadGuardrailTest*")
}

val integrationTest =
    tasks.register<Test>("integrationTest") {
        group = "verification"
        description = "Runs integration tests that install seccomp or Landlock filters, forcing a fresh JVM for each test."
        testClassesDirs = project.sourceSets["test"].output.classesDirs
        classpath = project.sourceSets["test"].runtimeClasspath
        useJUnitPlatform()
        jvmArgs("--enable-native-access=ALL-UNNAMED")
        systemProperty("kotest.framework.classpath.scanning.config.disable", "true")
        forkEvery = 1
        include("**/seccomp/**")
        include("**/landlock/**")
        include("**/SecurityPolicyTest*")
        include("**/ProcessContainmentInheritanceTest*")
        include("**/ContainedExecutorsTest*")
        include("**/VirtualThreadGuardrailTest*")
    }

tasks.check {
    dependsOn(integrationTest)
}
dependencies {
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.kotest.property)
    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotlinxCoroutines)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.slf4j.nop)
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

    // Core security logic must have high mutation coverage
    targetClasses.set(
        setOf(
            "io.mazewall.Policy*",
            "io.mazewall.BpfFilter*",
            "io.mazewall.SbobParser*",
            "io.mazewall.enforcer.FilterInstallationPlanner*",
            "io.mazewall.enforcer.PolicyCombining*",
        ),
    )

    // Exclude slow/fragile kernel tests and native bridges
    excludedClasses.set(
        setOf(
            "io.mazewall.LinuxNative*",
            "io.mazewall.RealNativeEngine*",
            "io.mazewall.IsolatedProcessTester*",
            "io.mazewall.MockNativeEngine*",
        ),
    )

    // Only run unit tests (fast, no kernel interaction)
    targetTests.set(
        setOf(
            "io.mazewall.PolicyTest",
            "io.mazewall.BpfFilterTest",
            "io.mazewall.SbobParserTest",
            "io.mazewall.enforcer.FilterInstallationPlannerTest",
            "io.mazewall.PolicyCombinePropertyTest",
        ),
    )

    jvmArgs.set(listOf("--enable-native-access=ALL-UNNAMED"))

    threads.set(System.getProperty("pitest.threads")?.toInt() ?: 4)
}
