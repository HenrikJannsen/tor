import org.gradle.api.GradleException
import java.nio.charset.StandardCharsets

val expectedReleaseJavaVersion = providers.gradleProperty("releaseBuild.javaVersion")

tasks.register("verifyGithubActionsSecurity") {
    group = "verification"
    description = "Verifies GitHub Actions workflows use pinned actions, fixed runner labels, the newest JDK of the " +
        "Java feature version, explicit permissions, no privileged triggers and no event data in scripts."

    val workflowFiles = fileTree(".github/workflows") {
        include("*.yml")
        include("*.yaml")
    }

    inputs.files(workflowFiles)
    inputs.property("expectedReleaseJavaVersion", expectedReleaseJavaVersion.orElse(""))
    outputs.upToDateWhen { false }
    // Copies of the values of the script and the project, which the configuration cache cannot store
    val releaseJavaVersion = expectedReleaseJavaVersion
    val rootDirectory = rootDir

    doLast {
        val expectedJavaVersion = releaseJavaVersion.orNull?.trim()
        val violations = mutableListOf<String>()
        val usesRegex = Regex("""^\s*-?\s*uses:\s*([^#\s]+)(?:\s+#\s*(.+))?\s*$""")
        val floatingRunnerRegex = Regex("""\b(ubuntu|macos|windows)-latest\b""", RegexOption.IGNORE_CASE)
        val fromJsonVariableRegex = Regex("""fromJson\(\s*vars\.""", RegexOption.IGNORE_CASE)
        val runnerSelectionRegex = Regex("""^\s*-?\s*(runs-on|os):""")
        val variableReferenceRegex = Regex("""\bvars\.""")
        val variableComparisonRegex = Regex("""\bvars\.[A-Za-z0-9_]+\s*==\s*'[^']*'""")
        val javaVersionRegex = Regex("""^\s*java-version:\s*([^#]+?)(?:\s+#.*)?$""")
        val javaMatrixRegex = Regex("""^\s*java:\s*\[([^]]+)]\s*(?:#.*)?$""")
        val checkLatestTrueRegex = Regex("""^\s*check-latest:\s*['"]?true['"]?\s*$""", RegexOption.IGNORE_CASE)
        val persistCredentialsFalseRegex = Regex("""^\s*persist-credentials:\s*['"]?false['"]?\s*$""", RegexOption.IGNORE_CASE)
        val validateWrappersTrueRegex = Regex("""^\s*validate-wrappers:\s*['"]?true['"]?\s*$""", RegexOption.IGNORE_CASE)
        val stepStartRegex = Regex("""^(\s*)-\s+[A-Za-z_][A-Za-z0-9_-]*\s*:.*$""")
        // Both run a workflow of the default branch with secrets and a write token for an event of a fork
        val privilegedTriggerRegex = Regex("""\b(pull_request_target|workflow_run)\b""")
        val topLevelPermissionsRegex = Regex("""^permissions\s*:""")
        val runKeyRegex = Regex("""^(\s*(?:-\s+)?)run\s*:(.*)$""")
        // Event data such as the title of a pull request comes from whoever opens it; inside a script it is shell code
        val eventExpressionRegex = Regex("""\$\{\{[^}]*\bgithub\.event\b""")

        // The workflows request the feature version of the minimum Java version, and check-latest makes setup-java take
        // the newest Azul build of it which exists for the runner. verifyBuildEnvironment checks the minimum.
        val expectedJavaFeatureVersion = expectedJavaVersion
            ?.takeIf { it.isNotEmpty() }
            ?.let { runCatching { Runtime.Version.parse(it).feature().toString() }.getOrNull() }
        if (expectedJavaVersion.isNullOrEmpty()) {
            violations += "Missing releaseBuild.javaVersion in gradle.properties"
        } else if (expectedJavaFeatureVersion == null) {
            violations += "releaseBuild.javaVersion $expectedJavaVersion is no Java version"
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

        fun withoutComment(line: String): String {
            val commentStart = Regex("""(^|\s)#""").find(line)
            return if (commentStart == null) line else line.substring(0, commentStart.range.first)
        }

        workflowFiles.files.sortedBy { it.path }.forEach { workflowFile ->
            val workflowPath = workflowFile.relativeTo(rootDirectory).path
            val lines = workflowFile.readLines(StandardCharsets.UTF_8)

            if (lines.none { topLevelPermissionsRegex.containsMatchIn(it) }) {
                violations += "$workflowPath has no top-level permissions block"
            }

            // The column of the run key of the script in which the current line is, or null outside of a script
            var runKeyColumn: Int? = null
            lines.forEachIndexed { index, line ->
                val lineNumber = index + 1

                if (privilegedTriggerRegex.containsMatchIn(withoutComment(line))) {
                    violations += "$workflowPath:$lineNumber uses a privileged trigger: ${line.trim()}"
                }

                val lineIndent = line.length - line.trimStart().length
                if (runKeyColumn != null && line.isNotBlank() && lineIndent <= runKeyColumn!!) {
                    runKeyColumn = null
                }
                val runKeyMatch = runKeyRegex.find(line)
                val scriptPart = when {
                    runKeyMatch != null -> {
                        runKeyColumn = runKeyMatch.groupValues[1].length
                        runKeyMatch.groupValues[2]
                    }
                    runKeyColumn != null -> line
                    else -> null
                }
                if (scriptPart != null && eventExpressionRegex.containsMatchIn(scriptPart)) {
                    violations += "$workflowPath:$lineNumber expands github.event in a run script; " +
                        "pass it in an environment variable instead"
                }
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
                        if (setupJavaStepLines.none { checkLatestTrueRegex.matches(it) }) {
                            violations += "$workflowPath:$lineNumber uses actions/setup-java without check-latest: true"
                        }
                    }

                    // The wrapper checksums of this repository are written by this repository; only this check of
                    // setup-gradle compares the wrapper jar with the checksums which Gradle publishes
                    if (actionRef.startsWith("gradle/actions/setup-gradle@")) {
                        val setupGradleStepLines = stepLinesAfter(lines, index)
                        if (setupGradleStepLines.none { validateWrappersTrueRegex.matches(it) }) {
                            violations += "$workflowPath:$lineNumber uses gradle/actions/setup-gradle without validate-wrappers: true"
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
                    if (!javaVersion.startsWith("\${{") &&
                        expectedJavaFeatureVersion != null &&
                        javaVersion != expectedJavaFeatureVersion) {
                        violations += "$workflowPath:$lineNumber uses Java version $javaVersion but must use " +
                            "$expectedJavaFeatureVersion, the feature version of releaseBuild.javaVersion"
                    }
                }

                val javaMatrixMatch = javaMatrixRegex.find(line)
                if (javaMatrixMatch != null) {
                    javaMatrixMatch.groupValues[1]
                        .split(',')
                        .map { cleanYamlScalar(it) }
                        .filter { it.isNotEmpty() && !it.startsWith("\${{") }
                        .forEach {
                            if (expectedJavaFeatureVersion != null && it != expectedJavaFeatureVersion) {
                                violations += "$workflowPath:$lineNumber uses Java matrix version $it but must use " +
                                    "$expectedJavaFeatureVersion, the feature version of releaseBuild.javaVersion"
                            }
                        }
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
