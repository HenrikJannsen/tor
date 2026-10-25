pluginManagement {
    repositories {
        gradlePluginPortal()
    }
    includeBuild("build-logic")
}

plugins {
    id("bisq.gradle.toolchain_resolver.ToolchainResolverPlugin")
}

toolchainManagement {
    jvm {
        javaRepositories {
            repository("bisq_zulu") {
                resolverClass.set(bisq.gradle.toolchain_resolver.BisqToolchainResolver::class.java)
            }
        }
    }
}

include("tor-common")
include("jsocks")
include("jtorctl")
include("tor")
include("tor-local-network")
include("tor-platform")

rootProject.name = "tor"
