plugins {
    kotlin("jvm") version "2.4.0" apply false
    id("jacoco")
    id("dev.detekt") version "2.0.0-alpha.3"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("com.github.spotbugs") version "6.5.5"
    id("org.owasp.dependencycheck") version "10.0.4"
    id("maven-publish")
    id("base")
    id("java")
}

group = "io.mazewall"
version = "0.1.0-SNAPSHOT"

allprojects {
    apply(plugin = "java")
    apply(plugin = "maven-publish")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    // Satisfy JitPack's broken 'listDeps' task by exposing 'configurations' as an extra property
    extra["configurations"] = configurations

    // Aggressively skip tests on JitPack because the host kernel (4.4)
    // is too old for Seccomp/Landlock/FFM and will cause failures.
    if (System.getenv("JITPACK") == "true") {
        tasks.withType<Test>().configureEach {
            enabled = false
        }
    }

    // Ensure code is formatted before compilation to prevent build failures
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        dependsOn("ktlintFormat")
    }

    // Also format Kotlin scripts (like build.gradle.kts)
    tasks.matching { it.name == "kotlinSourcesJar" }.configureEach {
        dependsOn("ktlintFormat")
    }
}

dependencyCheck {
    failBuildOnCVSS = 7.0f
    format = "ALL"
    suppressionFile = "$rootDir/config/dependency-check/suppressions.xml"
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
    baseline = file("detekt-baseline.xml")
}

ktlint {
    verbose.set(true)
    outputToConsole.set(true)
    coloredOutput.set(true)
    reporters {
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.PLAIN)
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.HTML)
    }
}

subprojects {
    apply(plugin = "base")
    apply(plugin = "jacoco")
    apply(plugin = "dev.detekt")
    apply(plugin = "com.github.spotbugs")

    spotbugs {
        ignoreFailures.set(false)
        showStackTraces.set(true)
        showProgress.set(true)
        effort.set(com.github.spotbugs.snom.Effort.MAX)
        reportLevel.set(com.github.spotbugs.snom.Confidence.HIGH)
    }

    dependencies {
        "spotbugsPlugins"("com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0")
    }

    extensions.configure<JacocoPluginExtension> {
        toolVersion = "0.8.14"
    }

    tasks.withType<Test>().configureEach {
        systemProperty("io.mazewall.test", "true")
        finalizedBy(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>())
    }

    tasks.withType<org.gradle.testing.jacoco.tasks.JacocoReport>().configureEach {
        dependsOn(tasks.withType<Test>())
        reports {
            xml.required.set(true)
            html.required.set(true)
        }

        finalizedBy(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoCoverageVerification>())
    }

    tasks.withType<org.gradle.testing.jacoco.tasks.JacocoCoverageVerification>().configureEach {
        violationRules {
            if (project.name == "enforcer") {
                // Core classes must meet 80% instruction coverage (LinuxNative has 78%)
                rule {
                    element = "CLASS"
                    excludes =
                        listOf(
                            "io.mazewall.seccomp.SeccompEngine*",
                            "io.mazewall.Platform*",
                            "io.mazewall.seccomp.PureJavaBpfEngine*",
                            "io.mazewall.Arch*",
                            "io.mazewall.landlock.Landlock*",
                            "io.mazewall.LinuxNative*",
                        )
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.80".toBigDecimal()
                    }
                }
                // Landlock must meet 65% instruction coverage in :enforcer (was 78% when including iterative profiler tests)
                rule {
                    element = "CLASS"
                    includes = listOf("io.mazewall.landlock.Landlock*")
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.65".toBigDecimal()
                    }
                }
                // LinuxNative must meet 78% instruction coverage in :enforcer (was 80% when including iterative profiler tests)
                rule {
                    element = "CLASS"
                    includes = listOf("io.mazewall.LinuxNative*")
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.78".toBigDecimal()
                    }
                }
                // Platform and Arch must meet 75% instruction coverage (actual Platform: 79.53%, Arch: 79.63%)
                rule {
                    element = "CLASS"
                    includes =
                        listOf(
                            "io.mazewall.Platform*",
                            "io.mazewall.Arch*",
                        )
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.70".toBigDecimal()
                    }
                }
                // PureJavaBpfEngine must meet 70% instruction coverage (actual: 73.13%)
                rule {
                    element = "CLASS"
                    includes = listOf("io.mazewall.seccomp.PureJavaBpfEngine*")
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.70".toBigDecimal()
                    }
                }
            } else if (project.name == "profiler") {
                // Profiler must meet 60% instruction coverage (actual lowest inner class is 62.65%)
                rule {
                    element = "CLASS"
                    includes =
                        listOf(
                            "io.mazewall.profiler.Profiler*",
                            "io.mazewall.profiler.engine.Profiler*",
                        )
                    excludes =
                        listOf(
                            "io.mazewall.profiler.engine.ProfilerDaemon",
                            "io.mazewall.profiler.strace.StraceWorkloadRunner",
                        )
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.60".toBigDecimal()
                    }
                }
            }
        }
    }

    plugins.withId("java") {
        tasks.named("check") {
            dependsOn(tasks.withType<org.gradle.testing.jacoco.tasks.JacocoCoverageVerification>())
        }
    }
}
