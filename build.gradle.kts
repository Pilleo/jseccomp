import org.gradle.api.publish.PublishingExtension

plugins {
    kotlin("jvm") version "2.4.0" apply false
    id("jacoco")
    id("dev.detekt") version "2.0.0-alpha.3"
    id("org.jlleitschuh.gradle.ktlint") version "14.2.0"
    id("com.github.spotbugs") version "6.5.5"
    id("org.owasp.dependencycheck") version "10.0.4"
    id("info.solidsoft.pitest") version "1.19.0" apply false
    id("base")
}

allprojects {
    group = "io.mazewall"
    version = "0.0.1-prealpha-SNAPSHOT"

    repositories {
        mavenCentral()
    }

    apply(plugin = "org.jlleitschuh.gradle.ktlint")

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
    apply(plugin = "java")
    apply(plugin = "maven-publish")
    apply(plugin = "base")
    apply(plugin = "jacoco")
    apply(plugin = "dev.detekt")
    apply(plugin = "com.github.spotbugs")

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
                rule {
                    element = "BUNDLE"
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.85".toBigDecimal()
                    }
                }
                rule {
                    element = "CLASS"
                    includes = listOf("io.mazewall.landlock.Landlock*")
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.70".toBigDecimal()
                    }
                }
            } else if (project.name == "profiler") {
                rule {
                    element = "BUNDLE"
                    limit {
                        counter = "INSTRUCTION"
                        value = "COVEREDRATIO"
                        minimum = "0.65".toBigDecimal()
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
