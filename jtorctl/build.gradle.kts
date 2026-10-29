plugins {
    id("bisq.java-conventions")
}

dependencies {
    "torPlatform"(platform(project(":tor-platform")))
}
