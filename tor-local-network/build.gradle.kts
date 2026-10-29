plugins {
    id("bisq.java-conventions")
    id("bisq.java-integration-tests")
    application
}

application {
    mainClass.set("bisq.network.tor.local_network.Main")
}

dependencies {
    "torPlatform"(platform(project(":tor-platform")))

    implementation(project(":tor-common"))
    implementation(project(":tor"))
    implementation(project(":jtorctl"))

    // Main is a program of its own, so it brings the logging backend
    runtimeOnly(libs.logback.classic)
}
