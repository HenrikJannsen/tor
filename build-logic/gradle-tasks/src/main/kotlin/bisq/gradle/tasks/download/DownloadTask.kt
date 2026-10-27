package bisq.gradle.tasks.download

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.logging.Logger
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.io.IOException
import java.net.URI
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption

@CacheableTask
abstract class DownloadTask : DefaultTask() {
    companion object {
        // Without them a stalled connection holds the build until the limit of the CI job. The read timeout applies to
        // each read, so a slow download which still makes progress goes on.
        private const val CONNECT_TIMEOUT_MILLIS = 30_000
        private const val READ_TIMEOUT_MILLIS = 60_000

        /**
         * Downloads [url] into [file], and once more if the first attempt fails, for example at a timeout. The file is
         * replaced only by a complete download.
         */
        fun downloadWithOneRetry(
            url: URL,
            file: File,
            connectTimeoutMillis: Int,
            readTimeoutMillis: Int,
            logger: Logger
        ) {
            try {
                downloadOnce(url, file, connectTimeoutMillis, readTimeoutMillis)
            } catch (e: IOException) {
                logger.warn("The download of $url failed ($e). Trying once more.")
                downloadOnce(url, file, connectTimeoutMillis, readTimeoutMillis)
            }
        }

        private fun downloadOnce(url: URL, file: File, connectTimeoutMillis: Int, readTimeoutMillis: Int) {
            val connection = url.openConnection()
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            val partFile = file.resolveSibling("${file.name}.part").toPath()
            try {
                connection.getInputStream().use { inputStream ->
                    Files.copy(inputStream, partFile, StandardCopyOption.REPLACE_EXISTING)
                }
                Files.move(partFile, file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } finally {
                Files.deleteIfExists(partFile)
            }
        }
    }

    @get:Input
    abstract val downloadUrl: Property<String>

    // The --offline option of Gradle only governs the dependency resolution. The task honours it as well, so that a
    // build which claims to be offline opens no connection. Not an input: the content of the download does not
    // depend on it.
    @get:Internal
    abstract val offline: Property<Boolean>

    @get:OutputFile
    abstract val outputFile: RegularFileProperty

    @TaskAction
    fun download() {
        if (offline.getOrElse(false)) {
            val file = outputFile.get().asFile
            if (file.isFile && file.length() > 0) {
                logger.lifecycle("Gradle runs offline, keeping the downloaded file $file")
                return
            }
            throw GradleException("Gradle runs offline (--offline) and $file is not downloaded yet. " +
                    "Run the build once without --offline.")
        }
        downloadFile()
    }

    private fun downloadFile() {
        val url = URI.create(downloadUrl.get()).toURL()
        logger.lifecycle("Downloading: $url")
        downloadWithOneRetry(url, outputFile.get().asFile, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, logger)
    }
}
