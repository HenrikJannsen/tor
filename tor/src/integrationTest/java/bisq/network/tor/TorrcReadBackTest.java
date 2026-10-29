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

package bisq.network.tor;

import bisq.network.tor.common.torrc.BaseTorrcGenerator;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.common.torrc.TorrcSyntax;
import bisq.network.tor.controller.PasswordDigest;
import bisq.network.tor.installer.TorInstaller;
import bisq.network.tor.process.BundledTorLibraries;
import bisq.network.tor.process.TorDirectories;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The bundled tor reads the torrc of Bisq as Bisq means it. Tor ends an unquoted value at "#", continues an entry whose
 * line ends with a backslash and drops the white space at both ends of a value. Bisq writes such a value as a quoted
 * string, or refuses it. tor --dump-config prints each option as tor has read it.
 */
@Timeout(60)
class TorrcReadBackTest {
    @TempDir
    static Path bundleDir;
    private static TorDirectories bundleDirectories;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void installTheBundle() {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
                "The paths of the test hold characters which Windows does not allow");
        assumeTrue(TorrcReadBackTest.class.getClassLoader().getResource("tor.zip") != null,
                "The build packaged no Tor bundle");
        bundleDirectories = new TorDirectories(bundleDir);
        new TorInstaller(bundleDirectories.getBinaryDirPath()).installIfNotUpToDate();
    }

    // The data directory of the application can hold "#", quotes and backslashes.
    @Test
    void torReadsThePathsOfTheTorrcOfTheEmbeddedTorWhole() throws Exception {
        var torDirectories = new TorDirectories(tempDir.resolve("Bisq#1 \"a\" \\b").resolve("tor"));
        Files.createDirectories(torDirectories.getDataDirPath());
        Map<String, String> torrc = TorrcClientConfigFactory.builder()
                .dataDirPath(torDirectories.getDataDirPath())
                .hashedControlPassword(PasswordDigest.generateDigest())
                .controlPort(19051)
                .socksPort(19050)
                .build()
                .torrcClientConfigMap(Map.of());
        TorService.putBundledGeoIpFiles(torrc, torDirectories);
        new TorrcFileGenerator(torDirectories.getTorrcPath(), torrc, Set.of()).generate();

        assertThat(readByTor(torDirectories.getTorrcPath()))
                .containsEntry("DataDirectory", torDirectories.getDataDirPath().toAbsolutePath().toString())
                .containsEntry("GeoIPFile", torDirectories.getBundledGeoIpFilePath().toAbsolutePath().toString())
                .containsEntry("GeoIPv6File", torDirectories.getBundledGeoIpv6FilePath().toAbsolutePath().toString());
    }

    // The relays of a private test network write their log and their control port into their data directory.
    @Test
    void torReadsTheLogFileAndThePortFileOfTheBaseTorrcWhole() throws Exception {
        Path dataDir = Files.createDirectories(tempDir.resolve("network#1").resolve("relay"));
        Map<String, String> torrc = BaseTorrcGenerator.builder()
                .dataDirPath(dataDir)
                .hashedControlPassword(PasswordDigest.generateDigest().getHashedPassword())
                .isTestNetwork(true)
                .build()
                .generate();
        Path torrcPath = tempDir.resolve("torrc");
        new TorrcFileGenerator(torrcPath, torrc, Set.of()).generate();

        assertThat(readByTor(torrcPath))
                .containsEntry("DataDirectory", dataDir.toAbsolutePath().toString())
                .containsEntry("ControlPortWriteToFile",
                        dataDir.resolve("control").resolve("control").toAbsolutePath().toString())
                .containsEntry("Log", "debug file " + dataDir.resolve("debug.log").toAbsolutePath());
    }

    @ParameterizedTest
    @ValueSource(strings = {"a usual value", "a#b", "\"starts with a quote", "ends with a backslash\\",
            " white space at both ends\t", "a quote \" and a backslash \\ inside"})
    void torReadsAValueOfTheTorrcSyntaxWhole(String value) throws Exception {
        Path torrcPath = Files.writeString(tempDir.resolve("torrc"), "ContactInfo " + TorrcSyntax.toValue(value) +
                "\n");

        assertThat(readByTor(torrcPath)).containsEntry("ContactInfo", value);
    }

    // Bisq refuses these values in the torrc overrides and in bridge lines.
    @ParameterizedTest
    @ValueSource(strings = {"a#b", "ends with a backslash\\", "\"quoted\" and more", "\"not closed"})
    void torDoesNotReadAValueWhichTheTorrcSyntaxRefusesAsItIsWritten(String value) throws Exception {
        assertThat(TorrcSyntax.findValueProblem(value)).isPresent();
        Path torrcPath = Files.writeString(tempDir.resolve("torrc"), "ContactInfo " + value + "\nNickname Sentinel\n");

        tryReadByTor(torrcPath).ifPresent(options -> assertThat(options.get("ContactInfo")).isNotEqualTo(value));
    }

    private Map<String, String> readByTor(Path torrcPath) throws IOException, InterruptedException {
        return tryReadByTor(torrcPath).orElseThrow(() -> new AssertionError("tor refused " + torrcPath));
    }

    /**
     * @return the options as tor --dump-config short prints them, with quoted values decoded, or empty if tor refuses
     * the torrc
     */
    private Optional<Map<String, String>> tryReadByTor(Path torrcPath) throws IOException, InterruptedException {
        Path emptyFile = Files.writeString(tempDir.resolve("empty"), "");
        var processBuilder = new ProcessBuilder(bundleDirectories.getBundledTorBinaryPath().toAbsolutePath().toString(),
                "--dump-config", "short",
                "-f", torrcPath.toAbsolutePath().toString(),
                "--defaults-torrc", emptyFile.toAbsolutePath().toString());
        BundledTorLibraries.applyToEnvironment(processBuilder.environment(), bundleDirectories.getBinaryDirPath());
        processBuilder.environment().put("OPENSSL_CONF", emptyFile.toAbsolutePath().toString());
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
        if (process.exitValue() != 0) {
            return Optional.empty();
        }
        Map<String, String> options = new HashMap<>();
        output.lines()
                .map(line -> line.split(" ", 2))
                .filter(parts -> parts.length == 2)
                .forEach(parts -> options.put(parts[0], decode(parts[1])));
        return Optional.of(options);
    }

    // tor prints a value which it would not read whole as a quoted string.
    private static String decode(String value) {
        return value.startsWith("\"") ? TorrcSyntax.decodeQuotedString(value) : value;
    }
}
