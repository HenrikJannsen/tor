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

import com.sun.net.httpserver.HttpServer;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigException;
import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Bisq 2 merges its program arguments, its JVM options, bisq.conf in its data directory and its resources into one
 * configuration. The torrc overrides of bisq.conf, a file which Bisq 2 also writes itself, are the overrides of a
 * configuration file. The values reach Tor as text.
 */
class TorTransportConfigTest {
    private static final String TRANSPORT_CONFIG = """
            bootstrapTimeout = 240
            hsUploadTimeout = 120
            testNetwork = false
            directoryAuthorities = []
            torrcOverrides {}
            useExternalTor = false
            """;

    @TempDir
    Path dataDir;

    @Test
    void theOverridesOfBisqConfAreOverridesOfAConfigurationFile() throws IOException {
        Config config = bisqConf("torrcOverrides { AccelName = \"engine\", Log = \"notice stdout\" }")
                .withFallback(ConfigFactory.parseString(TRANSPORT_CONFIG));

        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), config);

        assertThat(transportConfig.getTorrcOverrides()).containsEntry("AccelName", "engine");
        assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys()).containsExactlyInAnyOrder("AccelName", "Log");
        assertThat(transportConfig.getConfigFileTorrcOverrides().getHint())
                .contains("-Dapplication.network.configByTransportType.tor.torrcOverrides.<name>=<value>")
                .contains("bisq.conf");
    }

    // bisq.conf can include a URL. Its values have the URL as origin and no file name.
    @Test
    void theOverridesWhichBisqConfIncludesFromAUrlAreOverridesOfAConfigurationFile() throws IOException {
        byte[] included = "ClientTransportPlugin = \"obfs4 exec /tmp/x\"\nAccelName = engine\n"
                .getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/included.conf", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/hocon");
            exchange.sendResponseHeaders(200, included.length);
            exchange.getResponseBody().write(included);
            exchange.close();
        });
        server.start();
        try {
            Config config = bisqConf("torrcOverrides { include url(\"http://127.0.0.1:" +
                    server.getAddress().getPort() + "/included.conf\") }")
                    .withFallback(ConfigFactory.parseString(TRANSPORT_CONFIG));

            TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), config);

            assertThat(transportConfig.getTorrcOverrides()).containsEntry("AccelName", "engine");
            assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys())
                    .containsExactlyInAnyOrder("ClientTransportPlugin", "AccelName");
        } finally {
            server.stop(0);
        }
    }

    // Program arguments and JVM options come from the command line, and the default configuration of Bisq 2 is a
    // resource of the application.
    @Test
    void theOverridesOfTheCommandLineAndOfTheResourcesAreNot() {
        Config programArguments = ConfigFactory.parseMap(Map.of("torrcOverrides.ClientTransportPlugin",
                "obfs4 exec /usr/bin/lyrebird"));
        // In the test the resource comes from a directory, so that it has a file name, as in an IDE
        Config resource = ConfigFactory.parseResources("torrc-overrides-of-a-resource.conf");

        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), programArguments
                .withFallback(resource)
                .withFallback(ConfigFactory.parseString(TRANSPORT_CONFIG))
                .resolve());

        assertThat(resource.getValue("torrcOverrides.AccelName").origin().filename()).isNotNull();
        assertThat(transportConfig.getTorrcOverrides()).containsOnlyKeys("ClientTransportPlugin", "AccelName");
        assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys()).isEmpty();
    }

    // A program argument wins over bisq.conf, so Tor gets the value of the command line.
    @Test
    void anOverrideOfBisqConfWhichTheCommandLineReplacesIsNot() throws IOException {
        Config config = ConfigFactory.parseMap(Map.of("torrcOverrides.AccelName", "trusted"))
                .withFallback(bisqConf("torrcOverrides { AccelName = \"engine\", AccelDir = \"/tmp\" }"))
                .withFallback(ConfigFactory.parseString(TRANSPORT_CONFIG));

        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), config);

        assertThat(transportConfig.getTorrcOverrides()).containsEntry("AccelName", "trusted");
        assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys()).containsExactly("AccelDir");
    }

    @Test
    void aConfigurationWithoutOverridesHasNoOverridesOfAConfigurationFile() {
        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"),
                ConfigFactory.parseString(TRANSPORT_CONFIG));

        assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys()).isEmpty();
    }

    // Bisq 2 turns the values of program arguments and JVM options into numbers and booleans where it can, and a value
    // of bisq.conf without quotes is one as well. Tor gets the text.
    @Test
    void numbersAndBooleansReachTorAsText() throws IOException {
        Config config = ConfigFactory.parseMap(Map.of("torrcOverrides.NumEntryGuards", 3,
                        "torrcOverrides.ClientOnly", true))
                .withFallback(bisqConf(
                        "torrcOverrides { AvoidDiskWrites = 1, Nickname = 0123, MaxMemInQueues = 512 MB }"))
                .withFallback(ConfigFactory.parseString(TRANSPORT_CONFIG));

        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), config);

        assertThat(transportConfig.getTorrcOverrides())
                .containsEntry("NumEntryGuards", "3")
                .containsEntry("ClientOnly", "true")
                .containsEntry("AvoidDiskWrites", "1")
                .containsEntry("Nickname", "0123")
                .containsEntry("MaxMemInQueues", "512 MB");
        assertThat(transportConfig.getConfigFileTorrcOverrides().getKeys())
                .containsExactlyInAnyOrder("AvoidDiskWrites", "Nickname", "MaxMemInQueues");
    }

    // A list would be several entries of one key, which the overrides cannot express
    @Test
    void aListIsNoTorrcValue() {
        Config config = ConfigFactory.parseString(TRANSPORT_CONFIG.replace("torrcOverrides {}",
                "torrcOverrides { Bridge = [\"192.0.2.1:443\", \"192.0.2.2:443\"] }"));

        assertThatThrownBy(() -> TorTransportConfig.from(Path.of("tor"), config))
                .isInstanceOf(ConfigException.WrongType.class)
                .hasMessageContaining("Bridge");
    }

    @Test
    void theDirectoryAuthoritiesOfATestNetworkTakeTheirPortsAsNumbersOrText() {
        Config config = ConfigFactory.parseString(TRANSPORT_CONFIG.replace("directoryAuthorities = []", """
                directoryAuthorities = [{nickname = da, orPort = 9001, v3Ident = "ABC", dirPort = "9030",
                    relayFingerprint = "DEF"}]"""));

        TorTransportConfig transportConfig = TorTransportConfig.from(Path.of("tor"), config);

        assertThat(transportConfig.getDirectoryAuthorities()).singleElement().satisfies(authority -> {
            assertThat(authority.getNickname()).isEqualTo("da");
            assertThat(authority.getOrPort()).isEqualTo(9001);
            assertThat(authority.getDirPort()).isEqualTo(9030);
        });
    }

    private Config bisqConf(String content) throws IOException {
        Path bisqConf = Files.writeString(dataDir.resolve("bisq.conf"), content);
        return ConfigFactory.parseFile(bisqConf.toFile());
    }
}
