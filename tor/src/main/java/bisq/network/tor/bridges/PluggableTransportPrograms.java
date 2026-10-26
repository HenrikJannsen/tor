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

package bisq.network.tor.bridges;

import bisq.network.tor.common.platform.OS;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.TorDirectories;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

/**
 * Finds the programs of the pluggable transports for the {@code ClientTransportPlugin} entries of the torrc.
 * <p>
 * Tor splits such an entry at white space, so the path of a program must not contain any. The Bisq data directory of
 * macOS is below "Application Support", and on Windows the user name can contain a space. Bisq therefore starts Tor in
 * the directory of the bundle and passes the path of a bundled program relative to it, as Tor Browser and netlayer
 * did. On Linux the bundle has no programs for ARM64, so the program can also come from PATH.
 */
public final class PluggableTransportPrograms {
    private PluggableTransportPrograms() {
    }

    /**
     * @param bundleDirPath the directory of the installed bundle, which is the working directory of Tor
     * @param programName   the program name of pt_config.json, for example lyrebird
     * @return the path for the torrc, or empty if the program is missing
     */
    public static Optional<String> find(Path bundleDirPath, String programName) {
        return find(bundleDirPath, programName, OS.isWindows(), OS.isLinux(), System.getenv("PATH"));
    }

    static Optional<String> find(Path bundleDirPath,
                                 String programName,
                                 boolean isWindows,
                                 boolean isLinux,
                                 String pathEnvironmentVariable) {
        List<String> fileNames = isWindows ? List.of(programName + ".exe", programName) : List.of(programName);
        for (String fileName : fileNames) {
            Path bundledProgramPath = bundleDirPath.resolve(TorDirectories.PLUGGABLE_TRANSPORTS_DIR_NAME)
                    .resolve(fileName);
            if (Files.isRegularFile(bundledProgramPath) && (isWindows || Files.isExecutable(bundledProgramPath))) {
                return Optional.of(Paths.get(TorDirectories.PLUGGABLE_TRANSPORTS_DIR_NAME, fileName).toString());
            }
        }
        if (!isLinux) {
            return Optional.empty();
        }
        return EmbeddedTorProcess.findExecutableInPath(pathEnvironmentVariable, programName)
                .map(Path::toString)
                .filter(path -> path.chars().noneMatch(Character::isWhitespace));
    }
}
