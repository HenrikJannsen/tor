package bisq.gradle.tor_binary

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import javax.inject.Inject

/**
 * Gives the Tor binaries of the processed expert bundle an ad-hoc signature on macOS. Gradle 9 has no Project.exec,
 * and the configuration cache does not allow a task to use the project when it runs, so ExecOperations is injected.
 */
abstract class SignMacOsTorBinaryTask : DefaultTask() {

    @get:Inject
    abstract val execOperations: ExecOperations

    @get:Internal
    abstract val torBinaryDir: DirectoryProperty

    @TaskAction
    fun sign() {
        val codesignFile = File("/usr/bin/codesign")
        if (!codesignFile.canExecute()) {
            throw GradleException("Cannot ad-hoc sign bundled Tor: /usr/bin/codesign is not executable.")
        }

        torBinaryDir.get().asFile.walkTopDown()
            .filter { it.isFile }
            .filter { isMacOsCodeSignCandidate(it) }
            .sortedWith(compareBy<File> { it.name == "tor" }.thenBy { it.absolutePath })
            .forEach { binary ->
                execOperations.exec {
                    commandLine(codesignFile.absolutePath, "--force", "--sign", "-", binary.absolutePath)
                }
            }
    }

    private fun isMacOsCodeSignCandidate(file: File): Boolean {
        return file.name == "tor" ||
                file.name.endsWith(".dylib") ||
                file.name == "lyrebird" ||
                file.name == "conjure-client"
    }
}
