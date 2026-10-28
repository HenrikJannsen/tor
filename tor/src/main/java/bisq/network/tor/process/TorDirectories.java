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
 * <p>
 * Only {@link #dataDirPath} is writable for a sandboxed Tor. Bisq writes everything else, and Tor must not be able to
 * change it: otherwise a compromised Tor could replace a file that Bisq later executes, reads or writes outside the
 * sandbox. The Tor directory can also hold files of the application, for example the onion service key of Bisq 1 in
 * {@code hiddenservice}.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class TorDirectories {
    public static final String EXTERNAL_TOR_CONFIG_FILE_NAME = "external_tor.config";
    public static final String PLUGGABLE_TRANSPORTS_DIR_NAME = "pluggable_transports";
    static final String BINARY_DIR_NAME = "bin";
    static final String DATA_DIR_NAME = "data";
    static final String SANDY_DIR_NAME = "sandy";

    private final Path baseDirPath;
    // The installed files of the Tor expert bundle: binary, libraries, pluggable transports and GeoIP files.
    private final Path binaryDirPath;
    // The DataDirectory of Tor.
    private final Path dataDirPath;
    private final Path torrcPath;
    // The log of Tor (Tor logs to its standard output).
    private final Path stdoutLogPath;
    private final Path stderrLogPath;
    // The sandy binary, outside every path which Tor may write
    private final Path sandyDirPath;
    private final Path externalTorConfigPath;

    public TorDirectories(Path baseDirPath) {
        this.baseDirPath = baseDirPath;
        binaryDirPath = baseDirPath.resolve(BINARY_DIR_NAME);
        dataDirPath = baseDirPath.resolve(DATA_DIR_NAME);
        torrcPath = baseDirPath.resolve("torrc");
        stdoutLogPath = baseDirPath.resolve("tor-stdout.log");
        stderrLogPath = baseDirPath.resolve("tor-stderr.log");
        sandyDirPath = baseDirPath.resolve(SANDY_DIR_NAME);
        externalTorConfigPath = baseDirPath.resolve(EXTERNAL_TOR_CONFIG_FILE_NAME);
    }

    /**
     * @return the earlier log of Tor, which {@link EmbeddedTorProcess} moves aside when the log exceeds its size limit.
     * An application which shows, backs up or leaves out the logs of Tor takes their paths from here.
     */
    public Path getRotatedStdoutLogPath() {
        return EmbeddedTorProcess.rotatedStdoutLogPath(stdoutLogPath);
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
}
