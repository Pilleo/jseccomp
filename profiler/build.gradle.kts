plugins {
    kotlin("jvm")
    id("info.solidsoft.pitest")
}

kotlin {
    jvmToolchain(25)
}

sourceSets {
    create("integrationTest") {
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
    implementation(project(":enforcer"))
    implementation(libs.jackson.kotlin)
    testImplementation(kotlin("test"))
    testImplementation(libs.junit.jupiter.api)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.archunit.junit5)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.kotest.runner)
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

pitest {
    junit5PluginVersion.set("1.2.1")
    targetClasses.set(setOf("io.mazewall.profiler.*"))

    excludedClasses.set(
        setOf(
            "io.mazewall.profiler.internal.ProfilerDaemon*",
            "io.mazewall.profiler.engine.ProfilerTransport*",
        ),
    )

    jvmArgs.set(listOf("--enable-native-access=ALL-UNNAMED"))

    threads.set(System.getProperty("pitest.threads")?.toInt() ?: 4)
}
