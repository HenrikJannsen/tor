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
import com.google.common.annotations.VisibleForTesting;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.nio.file.Path;

/**
 * The files of the embedded Tor below the Tor directory of the application ({@code <app data dir>/tor}).
 */
@Getter
@ToString
@EqualsAndHashCode
public final class TorDirectories {
    public static final String EXTERNAL_TOR_CONFIG_FILE_NAME = "external_tor.config";
    public static final String PLUGGABLE_TRANSPORTS_DIR_NAME = "pluggable_transports";

    private final Path baseDirPath;
    // The installed files of the Tor expert bundle. On macOS and Windows: binary, libraries, pluggable transports and
    // GeoIP files. On Linux, where Bisq uses the tor of the system: the pluggable transports.
    private final Path binaryDirPath;
    // The DataDirectory of Tor.
    private final Path dataDirPath;
    private final Path torrcPath;
    private final Path stdoutLogPath;
    private final Path stderrLogPath;
    private final Path externalTorConfigPath;

    public TorDirectories(Path baseDirPath) {
        this.baseDirPath = baseDirPath;
        // The Tor directory holds everything: it is also the binary and the data directory.
        binaryDirPath = baseDirPath;
        dataDirPath = baseDirPath;
        torrcPath = baseDirPath.resolve("torrc");
        stdoutLogPath = baseDirPath.resolve("tor-stdout.log");
        stderrLogPath = baseDirPath.resolve("tor-stderr.log");
        externalTorConfigPath = baseDirPath.resolve(EXTERNAL_TOR_CONFIG_FILE_NAME);
    }

    // The GeoIP files of the bundled Tor, which the bundle installs next to the binary.
    public Path getBundledGeoIpFilePath() {
        return binaryDirPath.resolve("geoip");
    }

    public Path getBundledGeoIpv6FilePath() {
        return binaryDirPath.resolve("geoip6");
    }

    // An empty OpenSSL configuration for the bundled Tor
    public Path getOpenSslConfigPath() {
        return baseDirPath.resolve("openssl.cnf");
    }

    public Path getPluggableTransportsDirPath() {
        return binaryDirPath.resolve(PLUGGABLE_TRANSPORTS_DIR_NAME);
    }

    // The configuration of the pluggable transports and the built-in bridges of the Tor Browser version of the bundle
    public Path getPluggableTransportConfigPath() {
        return getPluggableTransportsDirPath().resolve("pt_config.json");
    }

    public Path getBundledTorBinaryPath() {
        return getBundledTorBinaryPath(OS.isWindows());
    }

    @VisibleForTesting
    Path getBundledTorBinaryPath(boolean isWindows) {
        return binaryDirPath.resolve(isWindows ? "tor.exe" : "tor");
    }

    public boolean isBundledTor(Path torBinaryPath) {
        return torBinaryPath.toAbsolutePath().normalize().startsWith(binaryDirPath.toAbsolutePath().normalize());
    }
}
