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

import bisq.network.tor.common.platform.OS;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TorDirectoriesTest {
    private static final Path BASE = Paths.get("/opt/app/tor").toAbsolutePath();
    private final TorDirectories directories = new TorDirectories(BASE);

    @Test
    void theFilesOfTheEmbeddedTorLieInTheTorDirectory() {
        Path bin = BASE.resolve("bin");
        assertThat(directories.getBaseDirPath()).isEqualTo(BASE);
        assertThat(directories.getBinaryDirPath()).isEqualTo(bin);
        assertThat(directories.getDataDirPath()).isEqualTo(BASE.resolve("data"));
        assertThat(directories.getSandyDirPath()).isEqualTo(BASE.resolve("sandy"));
        assertThat(directories.getSandyStatusRecordPath()).isEqualTo(BASE.resolve("sandy").resolve("run-status"));
        assertThat(directories.getDataModePath()).isEqualTo(BASE.resolve("data-mode"));
        assertThat(directories.getTorrcPath()).isEqualTo(BASE.resolve("torrc"));
        assertThat(directories.getStdoutLogPath()).isEqualTo(BASE.resolve("tor-stdout.log"));
        assertThat(directories.getStderrLogPath()).isEqualTo(BASE.resolve("tor-stderr.log"));
        assertThat(directories.getExternalTorConfigPath()).isEqualTo(BASE.resolve("external_tor.config"));
        assertThat(directories.getOpenSslConfigPath()).isEqualTo(BASE.resolve("openssl.cnf"));
        assertThat(directories.getBundledGeoIpFilePath()).isEqualTo(bin.resolve("geoip"));
        assertThat(directories.getBundledGeoIpv6FilePath()).isEqualTo(bin.resolve("geoip6"));
        assertThat(directories.getPluggableTransportsDirPath()).isEqualTo(bin.resolve("pluggable_transports"));
        assertThat(directories.getPluggableTransportConfigPath())
                .isEqualTo(bin.resolve("pluggable_transports").resolve("pt_config.json"));
    }

    // Bisq 2 leaves the logs of Tor out of its backup and opens them.
    @Test
    void theEarlierLogOfTorLiesNextToItsLog() {
        assertThat(directories.getRotatedStdoutLogPath()).isEqualTo(BASE.resolve("tor-stdout.log.1"));
        assertThat(directories.getRotatedStdoutLogPath())
                .isEqualTo(EmbeddedTorProcess.rotatedStdoutLogPath(directories.getStdoutLogPath()));
    }

    // The migration of the Tor directory takes the names of the layout from here, so a path of TorDirectories directly in
    // the Tor directory which the layout misses would count there as a file which the library does not know.
    @Test
    void theLayoutHasEveryPathOfTorDirectoriesInTheTorDirectory() throws Exception {
        List<Path> layoutEntries = directories.getLayoutEntries();
        for (Method method : TorDirectories.class.getMethods()) {
            if (method.getReturnType() == Path.class && method.getParameterCount() == 0) {
                Path path = (Path) method.invoke(directories);
                if (BASE.equals(path.getParent())) {
                    assertThat(layoutEntries).as(method.getName()).contains(path);
                }
            }
        }
        assertThat(layoutEntries).allMatch(entry -> BASE.equals(entry.getParent())).doesNotHaveDuplicates();
    }

    // A sandboxed Tor may write its data directory, so nothing which Bisq executes, reads or writes may lie there.
    @Test
    void nothingWhichBisqTrustsLiesInTheDataDirectory() {
        for (Path path : List.of(directories.getBinaryDirPath(), directories.getSandyDirPath(),
                directories.getSandyStatusRecordPath(), directories.getDataModePath(),
                directories.getTorrcPath(), directories.getStdoutLogPath(), directories.getStderrLogPath(),
                directories.getExternalTorConfigPath(), directories.getOpenSslConfigPath())) {
            assertThat(path.startsWith(directories.getDataDirPath())).as(path.toString()).isFalse();
        }
    }

    @Test
    void theBundledTorBinaryHasTheNameOfItsPlatform() {
        Path bin = BASE.resolve("bin");
        assertThat(directories.getBundledTorBinaryPath(true)).isEqualTo(bin.resolve("tor.exe"));
        assertThat(directories.getBundledTorBinaryPath(false)).isEqualTo(bin.resolve("tor"));
        assertThat(directories.getBundledTorBinaryPath())
                .isEqualTo(directories.getBundledTorBinaryPath(OS.isWindows()));
    }
}
