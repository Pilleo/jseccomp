plugins {
    kotlin("jvm")
    id("info.solidsoft.pitest")
}

kotlin {
    jvmToolchain(25)
}

sourceSets {
    test {
        java.srcDir(rootProject.file("src/sharedTest/kotlin"))
    }
    create("integrationTest") {
        java.srcDir(rootProject.file("src/sharedTest/kotlin"))
        compileClasspath += main.get().output + test.get().output
        runtimeClasspath += main.get().output + test.get().output
    }
}

// Associate integration tests with main and test to allow accessing internal members and test utilities
val kotlinExtension = extensions.getByType<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension>()
val kotlinCompilations = kotlinExtension.target.compilations
kotlinCompilations.named("integrationTest") {
    associateWith(kotlinCompilations.getByName("main"))
    associateWith(kotlinCompilations.getByName("test"))
}

val integrationTestImplementation by configurations.getting {
    extendsFrom(configurations.testImplementation.get())
}

val integrationTestRuntimeOnly by configurations.getting {
    extendsFrom(configurations.testRuntimeOnly.get())
}

val integrationTest =
    tasks.register<Test>("integrationTest") {
        group = "verification"
        testClassesDirs = sourceSets["integrationTest"].output.classesDirs
        classpath = sourceSets["integrationTest"].runtimeClasspath
        useJUnitPlatform()
        jvmArgs("--enable-native-access=ALL-UNNAMED")
        systemProperty("kotest.framework.classpath.scanning.config.disable", "true")
        forkEvery = 1
        testLogging {
            showStandardStreams = true
        }
    }

tasks.check {
    dependsOn(integrationTest)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    systemProperty("kotest.framework.classpath.scanning.config.disable", "true")
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

tasks.register<JavaExec>("runScratch") {
    group = "application"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("io.mazewall.Scratch")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

tasks.register<JavaExec>("runJvmFloor") {
    group = "verification"
    description = "Runs the synthetic JVM floor workload to exercise JIT, GC, Loom, and NIO subsystems."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.mazewall.enforcer.JvmFloorWorkload")
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

    timeoutConstInMillis.set(120000)
}
