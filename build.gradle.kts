plugins {
    kotlin("jvm") version "2.3.21" apply false
    id("jacoco")
    id("dev.detekt") version "2.0.0-alpha.3"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("com.github.spotbugs") version "6.5.5"
    id("org.owasp.dependencycheck") version "10.0.4"
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
    apply(plugin = "jacoco")
    apply(plugin = "dev.detekt")
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
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
            // Core classes must meet 80% instruction coverage
            rule {
                element = "CLASS"
                excludes =
                    listOf(
                        "io.mazewall.seccomp.SeccompEngine*",
                        "io.mazewall.Platform*",
                        "io.mazewall.seccomp.PureJavaBpfEngine*",
                        "io.mazewall.profiler.Profiler*",
                        "io.mazewall.Arch*",
                        "io.mazewall.landlock.Landlock*",
                    )
                limit {
                    counter = "INSTRUCTION"
                    value = "COVEREDRATIO"
                    minimum = "0.80".toBigDecimal()
                }
            }
            // Landlock must meet 78% instruction coverage (actual: 80.17%)
            rule {
                element = "CLASS"
                includes = listOf("io.mazewall.landlock.Landlock*")
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
                    minimum = "0.75".toBigDecimal()
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
            // Profiler must meet 60% instruction coverage (actual lowest inner class is 62.65%)
            rule {
                element = "CLASS"
                includes = listOf("io.mazewall.profiler.Profiler*")
                limit {
                    counter = "INSTRUCTION"
                    value = "COVEREDRATIO"
                    minimum = "0.60".toBigDecimal()
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
