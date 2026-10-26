/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.network.tor.installer;

import bisq.network.tor.common.archive.ZipFileExtractionFailedException;
import bisq.network.tor.common.archive.ZipFileExtractor;
import bisq.network.tor.common.platform.OS;
import bisq.network.tor.process.TorDirectories;
import com.google.common.annotations.VisibleForTesting;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

@Slf4j
public class TorBinaryZipExtractor {

    private static final String ARCHIVE_FILENAME = "tor.zip";

    private final Path destDirPath;

    public TorBinaryZipExtractor(Path destDirPath) {
        this.destDirPath = destDirPath;
    }

    public void extractBinary() throws IOException {
        extract(openBinaryZipAsStream());
    }

    @VisibleForTesting
    void extract(InputStream zipFileInputStream) throws IOException {
        try (ZipFileExtractor zipFileExtractor = new ZipFileExtractor(zipFileInputStream, destDirPath)) {
            zipFileExtractor.extractArchive();
            makeProgramsExecutable();
        }
        if (OS.isMacOs()) {
            MacOsCodeSignature.signUnsignedCode(destDirPath);
        }
    }

    private InputStream openBinaryZipAsStream() {
        InputStream inputStream = getClass()
                .getClassLoader()
                .getResourceAsStream(ARCHIVE_FILENAME);
        if (inputStream == null) {
            throw new ZipFileExtractionFailedException("Couldn't open resource: " + ARCHIVE_FILENAME);
        }
        return inputStream;
    }

    // The zip archive does not keep the file modes. On Linux, the archive has no tor, only the pluggable transports, so a
    // file named tor in the Tor directory is not part of the bundle.
    private void makeProgramsExecutable() throws IOException {
        if (!isMacOsOrLinux()) {
            return;
        }

        if (OS.isMacOs()) {
            makeExecutable(destDirPath.resolve("tor"));
        }

        Path pluggableTransportsDirPath = destDirPath.resolve(TorDirectories.PLUGGABLE_TRANSPORTS_DIR_NAME);
        if (Files.isDirectory(pluggableTransportsDirPath)) {
            try (Stream<Path> files = Files.list(pluggableTransportsDirPath)) {
                // The programs of the pluggable transports have no file extension, unlike pt_config.json and the
                // README files next to them.
                files.filter(Files::isRegularFile)
                        .filter(path -> !path.getFileName().toString().contains("."))
                        .forEach(this::makeExecutable);
            }
        }
    }

    private void makeExecutable(Path programPath) {
        if (!programPath.toFile().setExecutable(true)) {
            throw new ZipFileExtractionFailedException("Couldn't make " + programPath + " executable");
        }
    }

    private boolean isMacOsOrLinux() {
        return OS.isMacOs() || OS.isLinux();
    }
}
