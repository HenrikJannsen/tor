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

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PluggableTransportConfigTest {
    static PluggableTransportConfig readBundledConfig() throws IOException {
        // pt_config.json of the Tor expert bundle 15.0.25
        try (InputStream inputStream = PluggableTransportConfigTest.class.getResourceAsStream("/bridges/pt_config.json")) {
            return PluggableTransportConfig.parse(new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void readsTheTransportPluginsOfTheExpertBundle() throws IOException {
        PluggableTransportConfig config = readBundledConfig();

        assertThat(config.getTransportPlugins()).containsExactly(
                new PluggableTransportConfig.TransportPlugin(List.of("conjure"), "conjure-client",
                        List.of("-registerURL", "https://registration.refraction.network/api")),
                new PluggableTransportConfig.TransportPlugin(
                        List.of("meek_lite", "obfs2", "obfs3", "obfs4", "scramblesuit", "webtunnel"), "lyrebird",
                        List.of()),
                new PluggableTransportConfig.TransportPlugin(List.of("snowflake"), "lyrebird", List.of()));
    }

    @Test
    void readsTheBuiltInBridgesOfTheExpertBundle() throws IOException {
        PluggableTransportConfig config = readBundledConfig();

        assertThat(config.getBuiltInBridgesNames()).containsExactlyInAnyOrder("meek", "obfs4", "snowflake");
        assertThat(config.findBuiltInBridges("obfs4").orElseThrow())
                .hasSize(7)
                .allMatch(line -> line.startsWith("obfs4 "));
        assertThat(config.findBuiltInBridges("meek").orElseThrow())
                .singleElement()
                .matches(line -> line.startsWith("meek_lite "));
        assertThat(config.findBuiltInBridges("obfs3")).isEmpty();
    }

    @Test
    void aTypeWithoutBridgesIsUnknown() {
        PluggableTransportConfig config = PluggableTransportConfig.parse("""
                {"pluggableTransports": {}, "bridges": {"obfs4": [], "snowflake": ["snowflake 192.0.2.3:80 \
                0123456789ABCDEF0123456789ABCDEF01234567"]}}
                """);

        assertThat(config.getBuiltInBridgesNames()).containsExactly("snowflake");
        assertThat(config.findBuiltInBridges("obfs4")).isEmpty();
    }

    @Test
    void refusesATransportPluginWhichIsNotAProgramOfTheBundle() {
        assertThatThrownBy(() -> PluggableTransportConfig.parse("""
                {"pluggableTransports": {"x": "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"}, "bridges": {}}
                """))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unexpected transport plugin line");
        assertThatThrownBy(() -> PluggableTransportConfig.parse("""
                {"pluggableTransports": {"x": "ClientTransportPlugin obfs4 exec ${pt_path}../lyrebird"}, "bridges": {}}
                """))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PluggableTransportConfig.parse("{\"bridges\": {}}"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
