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

package bisq.network.tor.process;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

class TorDirectoriesTest {
    private static final Path BASE = Paths.get("/opt/app/tor").toAbsolutePath();
    private final TorDirectories directories = new TorDirectories(BASE);

    @Test
    void theFilesOfTheEmbeddedTorLieInTheTorDirectory() {
        assertThat(directories.getBaseDirPath()).isEqualTo(BASE);
        assertThat(directories.getBinaryDirPath()).isEqualTo(BASE);
        assertThat(directories.getDataDirPath()).isEqualTo(BASE);
        assertThat(directories.getTorrcPath()).isEqualTo(BASE.resolve("torrc"));
        assertThat(directories.getStdoutLogPath()).isEqualTo(BASE.resolve("tor-stdout.log"));
        assertThat(directories.getStderrLogPath()).isEqualTo(BASE.resolve("tor-stderr.log"));
        assertThat(directories.getExternalTorConfigPath()).isEqualTo(BASE.resolve("external_tor.config"));
    }

    @Test
    void onlyABinaryInTheTorDirectoryIsTheBundledTor() {
        assertThat(directories.isBundledTor(BASE.resolve("tor"))).isTrue();
        assertThat(directories.isBundledTor(Paths.get("/usr/bin/tor"))).isFalse();
        // The path is normalized, so one which leaves the Tor directory is not the bundled Tor.
        assertThat(directories.isBundledTor(BASE.resolve("..").resolve("other").resolve("tor"))).isFalse();
    }
}
