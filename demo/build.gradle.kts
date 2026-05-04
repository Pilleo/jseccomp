plugins {
    id("buildsrc.convention.kotlin-jvm")
}

dependencies {
    implementation(project(":utils"))
    testImplementation(kotlin("test"))
}
