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

package bisq.network.tor.local_network.da.keygen;

import bisq.network.tor.local_network.TorNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

public class RelayKeyGenProcess {
    private static final long TIMEOUT_SEC = 45;

    private final TorNode directoryAuthority;

    public RelayKeyGenProcess(TorNode directoryAuthority) {
        this.directoryAuthority = directoryAuthority;
    }

    /**
     * @throws IOException if tor did not write the keys, with the output of tor
     */
    public void generateKeys(String identityKeyFingerprint) throws IOException, InterruptedException {
        Path dataDirPath = directoryAuthority.getDataDirPath().toAbsolutePath();
        // Without a torrc of its own, tor reads the torrc of the system, whose options can stop it, for example a
        // HashedControlPassword which it refuses.
        Path emptyTorrcPath = dataDirPath.resolve("keygen-torrc");
        Files.writeString(emptyTorrcPath, "");
        Path logPath = dataDirPath.resolve("keygen.log");
        var processBuilder = new ProcessBuilder(
                "tor",
                "-f", emptyTorrcPath.toString(),
                "--defaults-torrc", emptyTorrcPath.toString(),
                "--list-fingerprint",
                "--DataDirectory", dataDirPath.toString(),
                "--ORPort", String.valueOf(directoryAuthority.getOrPort()),

                "--DirAuthority",
                directoryAuthority.getNickname() +
                        " orport=" + directoryAuthority.getOrPort() +
                        " v3ident=" + identityKeyFingerprint +
                        " 127.0.0.1:" + directoryAuthority.getDirPort() +
                        " ffffffffffffffffffffffffffffffffffffffff"
        );

        processBuilder.redirectErrorStream(true)
                .redirectOutput(logPath.toFile());

        Process process = processBuilder.start();
        if (!process.waitFor(TIMEOUT_SEC, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("tor --list-fingerprint did not finish within " + TIMEOUT_SEC + " seconds. Its " +
                    "output is in " + logPath);
        }
        if (process.exitValue() != 0) {
            throw new IOException("tor --list-fingerprint failed with exit code " + process.exitValue() + ":\n" +
                    Files.readString(logPath, StandardCharsets.UTF_8).strip());
        }
    }
}
