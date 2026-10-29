package bisq.gradle.tasks

import bisq.gradle.common.Platform
import bisq.gradle.common.Platform.*

interface PerPlatformUrlProvider {
    val urlPrefix: String

    val LINUX_X86_64_URL: String
    val MACOS_X86_64_URL: String
    val MACOS_ARM_64_URL: String
    val WIN_X86_64_URL: String

    /**
     * The URL of the binary of [platform], or null if there is none. An ARM64 platform without a binary of its own
     * does not get the binary of x86_64, so that no build packages programs of another architecture unnoticed.
     */
    fun urlFor(platform: Platform): String? {
        val urlSuffix = when (platform) {
            LINUX_X86_64 -> LINUX_X86_64_URL
            MACOS_X86_64 -> MACOS_X86_64_URL
            MACOS_ARM_64 -> MACOS_ARM_64_URL
            WIN_X86_64 -> WIN_X86_64_URL
            LINUX_ARM_64, WIN_ARM_64 -> return null
        }
        return urlPrefix + urlSuffix
    }
}
