import org.gradle.api.GradleException
import java.nio.charset.StandardCharsets

val expectedReleaseJavaVersion = providers.gradleProperty("releaseBuild.javaVersion")

tasks.register("verifyGithubActionsSecurity") {
    group = "verification"
    description = "Verifies GitHub Actions workflows use pinned actions and non-floating build environments."

    val workflowFiles = fileTree(".github/workflows") {
        include("*.yml")
        include("*.yaml")
    }

    inputs.files(workflowFiles)
    inputs.property("expectedReleaseJavaVersion", expectedReleaseJavaVersion.orElse(""))
    outputs.upToDateWhen { false }

    doLast {
        val expectedJavaVersion = expectedReleaseJavaVersion.orNull?.trim()
        val violations = mutableListOf<String>()
        val usesRegex = Regex("""^\s*-?\s*uses:\s*([^#\s]+)(?:\s+#\s*(.+))?\s*$""")
        val floatingRunnerRegex = Regex("""\b(ubuntu|macos|windows)-latest\b""", RegexOption.IGNORE_CASE)
        val fromJsonVariableRegex = Regex("""fromJson\(\s*vars\.""", RegexOption.IGNORE_CASE)
        val runnerSelectionRegex = Regex("""^\s*-?\s*(runs-on|os):""")
        val variableReferenceRegex = Regex("""\bvars\.""")
        val variableComparisonRegex = Regex("""\bvars\.[A-Za-z0-9_]+\s*==\s*'[^']*'""")
        val javaVersionRegex = Regex("""^\s*java-version:\s*([^#]+?)(?:\s+#.*)?$""")
        val javaMatrixRegex = Regex("""^\s*java:\s*\[([^]]+)]\s*(?:#.*)?$""")
        val exactJavaVersionRegex = Regex("""\d+\.\d+\.\d+""")
        val checkLatestTrueRegex = Regex("""^\s*check-latest:\s*['"]?true['"]?\s*$""", RegexOption.IGNORE_CASE)
        val checkLatestFalseRegex = Regex("""^\s*check-latest:\s*['"]?false['"]?\s*$""", RegexOption.IGNORE_CASE)
        val persistCredentialsFalseRegex = Regex("""^\s*persist-credentials:\s*['"]?false['"]?\s*$""", RegexOption.IGNORE_CASE)
        val stepStartRegex = Regex("""^(\s*)-\s+[A-Za-z_][A-Za-z0-9_-]*\s*:.*$""")

        if (expectedJavaVersion.isNullOrEmpty()) {
            violations += "Missing releaseBuild.javaVersion in gradle.properties"
        }

        fun cleanYamlScalar(value: String): String {
            return value.trim().trim('\'', '"')
        }

        fun stepLinesAfter(lines: List<String>, startIndex: Int): List<String> {
            val stepStartIndent = (startIndex downTo 0)
                .mapNotNull { stepStartRegex.find(lines[it]) }
                .firstOrNull()
                ?.groupValues
                ?.get(1)
                ?.length

            return lines.drop(startIndex + 1).takeWhile { line ->
                val nextStepStart = stepStartRegex.find(line)
                stepStartIndent == null ||
                    nextStepStart == null ||
                    nextStepStart.groupValues[1].length != stepStartIndent
            }
        }

        workflowFiles.files.sortedBy { it.path }.forEach { workflowFile ->
            val workflowPath = rootProject.relativePath(workflowFile)
            val lines = workflowFile.readLines(StandardCharsets.UTF_8)

            lines.forEachIndexed { index, line ->
                val lineNumber = index + 1
                val usesMatch = usesRegex.find(line)
                if (usesMatch != null) {
                    val actionRef = usesMatch.groupValues[1]
                    val versionComment = usesMatch.groupValues[2].trim()

                    if (!actionRef.startsWith("./")) {
                        val ref = actionRef.substringAfterLast('@', missingDelimiterValue = "")
                        if (!ref.matches(Regex("""[0-9a-fA-F]{40}"""))) {
                            violations += "$workflowPath:$lineNumber uses '$actionRef' without a full 40-character commit SHA"
                        }
                        if (versionComment.isEmpty()) {
                            violations += "$workflowPath:$lineNumber uses '$actionRef' without an inline version comment"
                        }
                    }

                    if (actionRef.startsWith("actions/checkout@")) {
                        val checkoutStepLines = stepLinesAfter(lines, index)
                        if (checkoutStepLines.none { persistCredentialsFalseRegex.matches(it) }) {
                            violations += "$workflowPath:$lineNumber uses actions/checkout without persist-credentials: false"
                        }
                    }

                    if (actionRef.startsWith("actions/setup-java@")) {
                        val setupJavaStepLines = stepLinesAfter(lines, index)
                        if (setupJavaStepLines.none { checkLatestFalseRegex.matches(it) }) {
                            violations += "$workflowPath:$lineNumber uses actions/setup-java without check-latest: false"
                        }
                    }
                }

                if (floatingRunnerRegex.containsMatchIn(line)) {
                    violations += "$workflowPath:$lineNumber uses a floating GitHub runner label: ${line.trim()}"
                }

                // Repository variables are not reviewed and not visible to this check. They may select between
                // checked-in runner labels, but must never provide a label themselves.
                val lineWithoutVariableComparisons = line.replace(variableComparisonRegex, "")
                if (fromJsonVariableRegex.containsMatchIn(lineWithoutVariableComparisons)) {
                    violations += "$workflowPath:$lineNumber parses a repository variable as JSON: ${line.trim()}"
                }
                if (runnerSelectionRegex.containsMatchIn(line) &&
                    variableReferenceRegex.containsMatchIn(lineWithoutVariableComparisons)) {
                    violations += "$workflowPath:$lineNumber takes a runner label from a repository variable: ${line.trim()}"
                }

                val javaVersionMatch = javaVersionRegex.find(line)
                if (javaVersionMatch != null) {
                    val javaVersion = cleanYamlScalar(javaVersionMatch.groupValues[1])
                    if (!javaVersion.startsWith("\${{") && !exactJavaVersionRegex.matches(javaVersion)) {
                        violations += "$workflowPath:$lineNumber uses a floating Java version: ${line.trim()}"
                    } else if (!javaVersion.startsWith("\${{") &&
                        !expectedJavaVersion.isNullOrEmpty() &&
                        javaVersion != expectedJavaVersion) {
                        violations += "$workflowPath:$lineNumber uses Java version $javaVersion but releaseBuild.javaVersion is $expectedJavaVersion"
                    }
                }

                val javaMatrixMatch = javaMatrixRegex.find(line)
                if (javaMatrixMatch != null) {
                    javaMatrixMatch.groupValues[1]
                        .split(',')
                        .map { cleanYamlScalar(it) }
                        .filter { it.isNotEmpty() && !it.startsWith("\${{") }
                        .forEach {
                            if (!exactJavaVersionRegex.matches(it)) {
                                violations += "$workflowPath:$lineNumber uses a floating Java matrix version: $it"
                            } else if (!expectedJavaVersion.isNullOrEmpty() && it != expectedJavaVersion) {
                                violations += "$workflowPath:$lineNumber uses Java matrix version $it but releaseBuild.javaVersion is $expectedJavaVersion"
                            }
                        }
                }

                if (checkLatestTrueRegex.matches(line)) {
                    violations += "$workflowPath:$lineNumber sets check-latest: true"
                }
            }
        }

        if (violations.isNotEmpty()) {
            throw GradleException(
                "GitHub Actions security verification failed:\n" +
                    violations.joinToString(separator = "\n") { "  - $it" }
            )
        }

        logger.lifecycle("Verified ${workflowFiles.files.size} GitHub Actions workflow files.")
    }
}
