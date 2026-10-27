plugins {
    id("bisq.java-conventions")
    id("bisq.java-integration-tests")
}

dependencies {
    "torPlatform"(platform(project(":tor-platform")))
}
