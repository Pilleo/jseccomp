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
    // version.set("1.8.0")
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

    extensions.configure<org.gradle.testing.jacoco.plugins.JacocoPluginExtension> {
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
                        "io.mazewall.profiler.ProfilerDaemon*",
                        "io.mazewall.seccomp.SeccompEngine*",
                        "io.mazewall.profiler.IterativeProfiler*",
                        "io.mazewall.Arch*",
                        "io.mazewall.Platform*",
                        "io.mazewall.profiler.Profiler*",
                        "io.mazewall.landlock.Landlock*",
                        "io.mazewall.seccomp.PureJavaBpfEngine*",
                    )
                limit {
                    counter = "INSTRUCTION"
                    value = "COVEREDRATIO"
                    minimum = "0.80".toBigDecimal()
                }
            }
            rule {
                element = "CLASS"
                includes =
                    listOf(
                        "io.mazewall.landlock.Landlock*",
                        "io.mazewall.seccomp.PureJavaBpfEngine*",
                        "io.mazewall.Platform*",
                    )
                limit {
                    counter = "INSTRUCTION"
                    value = "COVEREDRATIO"
                    minimum = "0.60".toBigDecimal()
                }
            }
            rule {
                element = "CLASS"
                includes = listOf("io.mazewall.Arch*")
                limit {
                    counter = "INSTRUCTION"
                    value = "COVEREDRATIO"
                    minimum = "0.40".toBigDecimal()
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
