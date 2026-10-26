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

import bisq.network.tor.common.platform.OS;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class TorBinaryZipExtractorTest {
    @TempDir
    Path torDir;

    @Test
    void theProgramsOfThePluggableTransportsBecomeExecutable() throws IOException {
        assumeTrue(OS.isLinux(), "The archive of Linux");
        // A file which is not part of the bundle, as the Whonix guide for Bisq 1 creates it
        Files.createFile(torDir.resolve("tor"));

        // The archive of Linux: only the pluggable transports, without tor
        new TorBinaryZipExtractor(torDir).extract(zip("pluggable_transports/lyrebird",
                "pluggable_transports/conjure-client",
                "pluggable_transports/pt_config.json",
                "pluggable_transports/README.CONJURE.md"));

        Path pluggableTransportsDir = torDir.resolve("pluggable_transports");
        assertThat(pluggableTransportsDir.resolve("lyrebird")).isExecutable();
        assertThat(pluggableTransportsDir.resolve("conjure-client")).isExecutable();
        assertThat(Files.isExecutable(pluggableTransportsDir.resolve("pt_config.json"))).isFalse();
        assertThat(Files.isExecutable(torDir.resolve("tor"))).isFalse();
    }

    private static ByteArrayInputStream zip(String... entryNames) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            for (String entryName : entryNames) {
                zipOutputStream.putNextEntry(new ZipEntry(entryName));
                zipOutputStream.write(entryName.getBytes(StandardCharsets.UTF_8));
                zipOutputStream.closeEntry();
            }
        }
        return new ByteArrayInputStream(outputStream.toByteArray());
    }
}
