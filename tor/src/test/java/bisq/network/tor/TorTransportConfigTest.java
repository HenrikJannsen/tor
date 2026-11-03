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

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Bisq 2 merges its program arguments, its JVM options, bisq.conf in its data directory and its resources into one
 * configuration. The torrc overrides of bisq.conf, a file which Bisq 2 also writes itself, are the overrides of a
 * configuration file.
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

    private Config bisqConf(String content) throws IOException {
        Path bisqConf = Files.writeString(dataDir.resolve("bisq.conf"), content);
        return ConfigFactory.parseFile(bisqConf.toFile());
    }
}
