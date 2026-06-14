import org.gradle.api.publish.PublishingExtension

plugins {
    alias(libs.plugins.kotlin)
    alias(libs.plugins.detekt)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.spotbugs)
    alias(libs.plugins.dependencyCheck)
    alias(libs.plugins.pitest) apply false
    id("jacoco")
    id("base")
}

allprojects {
    group = "io.mazewall"
    version = "0.0.1-prealpha-SNAPSHOT"

    repositories {
        mavenCentral()
    }

    if (!project.path.startsWith(":demos")) {
        apply(plugin = "org.jlleitschuh.gradle.ktlint")
        configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
            version.set("1.3.1")
            verbose.set(true)
            outputToConsole.set(true)
            coloredOutput.set(true)
            reporters {
                reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.PLAIN)
                reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.HTML)
            }
        }
        // Disable ktlint formatting/checking tasks because the ktlint engine (even 1.3.1+)
        // fails to parse Kotlin 2.x context parameters syntax ("context(arena: Arena)").
        // TODO: Re-enable these tasks once KtLint officially supports named context parameters syntax in Kotlin 2.4+.
        tasks.configureEach {
            if (name.contains("ktlint", ignoreCase = true)) {
                enabled = false
            }
        }
    }

    // JitPack Shim: Satisfy JitPack's broken 'listDeps' task by injecting
    // the missing 'configurations' property into the task instance.
    tasks.whenTaskAdded {
        if (name == "listDeps") {
            // Using extensions/extra to satisfy Groovy property resolution
            (this as? ExtensionAware)?.extra?.set("configurations", project.configurations)
        }
    }

    // Aggressively skip tests on JitPack because the host kernel (4.4)
    // is too old for Seccomp/Landlock/FFM and will cause failures.
    if (System.getenv("JITPACK") == "true") {
        tasks.withType<Test>().configureEach {
            enabled = false
        }
    }

    // Ensure code is formatted before compilation or check to prevent build failures
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        if (!project.path.startsWith(":demos")) {
            dependsOn("ktlintFormat")
        }
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_22)
            freeCompilerArgs.add("-Xcontext-parameters")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release.set(22)
    }

    tasks.matching { it.name == "ktlintCheck" || it.name == "ktlintTestSourceSetCheck" || it.name == "ktlintMainSourceSetCheck" }.configureEach {
        if (!project.path.startsWith(":demos")) {
            dependsOn("ktlintFormat")
        }
    }

    // Also format Kotlin scripts (like build.gradle.kts)
    tasks.matching { it.name == "kotlinSourcesJar" }.configureEach {
        if (!project.path.startsWith(":demos")) {
            dependsOn("ktlintFormat")
        }
    }
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    format = "ALL"
    suppressionFile = "$rootDir/config/dependency-check/suppressions.xml"
    System.getenv("NVD_API_KEY")?.takeIf { it.isNotBlank() }?.let {
        nvd.apiKey = it
    }
    // Disable OSS Index as it requires separate credentials and is currently failing in CI
    analyzers {
        ossIndexEnabled = false
    }
    // Skip checking demo projects since they are deliberately vulnerable
    skipProjects = listOf(":demos:cli-demo", ":demos:vulnerable-web-app")
    // Only scan production compile and runtime configurations to avoid scanning build tooling like detekt and ktlint
    scanConfigurations = listOf("compileClasspath", "runtimeClasspath")
}

tasks.named("dependencyCheckAnalyze").configure {
    onlyIf("NVD API Key is required for CI performance") {
        System.getenv("CI") != "true" || !System.getenv("NVD_API_KEY").isNullOrBlank()
    }
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    source.setFrom(files("src/main/kotlin"))
}

subprojects {
    if (project.path.startsWith(":demos")) {
        return@subprojects
    }
    apply(plugin = "java")
    apply(plugin = "maven-publish")
    apply(plugin = "base")
    apply(plugin = "jacoco")
    apply(plugin = "dev.detekt")
    apply(plugin = "com.github.spotbugs")

    detekt {
        baseline = file("$rootDir/config/detekt/${project.name}-baseline.xml")
        source.setFrom(files("src/main/kotlin"))
    }

    tasks.configureEach {
        if (name.startsWith("detekt")) {
            try {
                val method = this.javaClass.getMethod("getJdkHome")
                val property = method.invoke(this) as org.gradle.api.file.DirectoryProperty
                property.set(layout.projectDirectory.dir(providers.systemProperty("java.home")))
            } catch (_: NoSuchMethodException) {
                // Ignore tasks that do not have getJdkHome
            }
        }
    }

    extensions.configure<PublishingExtension> {
        repositories {
            System.getenv("GITHUB_ACTOR")?.let { actor ->
                maven {
                    name = "GitHubPackages"
                    url = uri("https://maven.pkg.github.com/Pilleo/mazewall")
                    credentials {
                        username = actor
                        password = System.getenv("GITHUB_TOKEN")
                    }
                }
            }
        }
    }

    spotbugs {
        ignoreFailures.set(false)
        showStackTraces.set(true)
        showProgress.set(true)
        effort.set(com.github.spotbugs.snom.Effort.MAX)
        reportLevel.set(com.github.spotbugs.snom.Confidence.HIGH)
        excludeFilter.set(file("$rootDir/config/spotbugs/exclude.xml"))
    }

    dependencies {
        "spotbugsPlugins"(
            rootProject.extensions
                .getByType<VersionCatalogsExtension>()
                .named("libs")
                .findLibrary("findsecbugs")
                .get(),
        )
    }

    extensions.configure<JacocoPluginExtension> {
        toolVersion =
            rootProject.extensions
                .getByType<VersionCatalogsExtension>()
                .named("libs")
                .findVersion("jacoco")
                .get()
                .requiredVersion
    }

    tasks.withType<Test>().configureEach {
        systemProperty("io.mazewall.test", "true")
        // Skip integration tests on host since they require container-level capabilities and seccomp filters.
        if (name == "integrationTest" && System.getenv("MAZEWALL_IN_CONTAINER") != "true") {
            enabled = false
        }
    }

    tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>().configureEach {
        // Enforce ordering so we aggregate execution data from both host unit tests and container integration tests
        mustRunAfter(rootProject.tasks.named("test"))
        dependsOn(tasks.withType<Test>())
        mustRunAfter(tasks.withType<Test>())
        executionData.setFrom(fileTree(project.layout.buildDirectory.dir("jacoco")).include("*.exec"))
        reports {
            xml.required.set(true)
            html.required.set(true)
        }
    }

    tasks.withType<org.gradle.testing.jacoco.tasks.JacocoCoverageVerification>().configureEach {
        // Enforce ordering so we aggregate execution data from both host unit tests and container integration tests
        mustRunAfter(rootProject.tasks.named("test"))
        dependsOn(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>())
        mustRunAfter(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>())
        executionData.setFrom(fileTree(project.layout.buildDirectory.dir("jacoco")).include("*.exec"))
        violationRules {
            if (project.name == "enforcer") {
                rule {
                    element = "BUNDLE"
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.70".toBigDecimal()
                    }
                }
                rule {
                    element = "CLASS"
                    includes = listOf("io.mazewall.landlock.Landlock*")
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.60".toBigDecimal()
                    }
                }
            } else if (project.name == "profiler") {
                rule {
                    element = "BUNDLE"
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.30".toBigDecimal()
                    }
                }
            }
        }
    }

    plugins.withId("java") {
        tasks.named("check") {
            dependsOn(tasks.withType<Test>())
            dependsOn(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>())
            dependsOn(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoCoverageVerification>())
        }
    }
}
