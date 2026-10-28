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

import bisq.network.tor.BridgeConfig;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BridgeTorrcEntriesTest {
    private static final String OBFS4_BRIDGE = "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 " +
            "cert=abc iat-mode=0";
    private static final String WEBTUNNEL_BRIDGE = "webtunnel [2001:db8::1]:443 " +
            "0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/path ver=0.0.1";
    private static final String SNOWFLAKE_BRIDGE = "snowflake 192.0.2.3:80 " +
            "0123456789ABCDEF0123456789ABCDEF01234567 fingerprint=0123456789ABCDEF0123456789ABCDEF01234567";
    private static final String VANILLA_BRIDGE = "192.0.2.4:9001 0123456789ABCDEF0123456789ABCDEF01234567";

    private final PluggableTransportConfig config = PluggableTransportConfigTest.readBundledConfig();

    BridgeTorrcEntriesTest() throws IOException {
    }

    @Test
    void theBuiltInBridgesUseTheProgramOfTheBundle() {
        List<Map.Entry<String, String>> entries = BridgeTorrcEntries.create(BridgeConfig.builtIn("obfs4"), config,
                program -> Optional.of("pluggable_transports/" + program));

        assertThat(entries.get(0)).isEqualTo(Map.entry("UseBridges", "1"));
        assertThat(entries.subList(1, 8)).allMatch(entry -> entry.getKey().equals("Bridge") &&
                entry.getValue().startsWith("obfs4 "));
        assertThat(entries.subList(8, entries.size())).containsExactly(
                Map.entry("ClientTransportPlugin", "obfs4 exec pluggable_transports/lyrebird"));
    }

    @Test
    void eachProgramGetsTheTransportsOfTheBridgesWhichUseIt() {
        BridgeConfig bridgeConfig = BridgeConfig.custom(List.of(SNOWFLAKE_BRIDGE, OBFS4_BRIDGE, WEBTUNNEL_BRIDGE,
                VANILLA_BRIDGE));

        List<Map.Entry<String, String>> entries = BridgeTorrcEntries.create(bridgeConfig, config,
                program -> Optional.of("pluggable_transports/" + program));

        assertThat(entries).containsExactly(
                Map.entry("UseBridges", "1"),
                Map.entry("Bridge", SNOWFLAKE_BRIDGE),
                Map.entry("Bridge", OBFS4_BRIDGE),
                Map.entry("Bridge", WEBTUNNEL_BRIDGE),
                Map.entry("Bridge", VANILLA_BRIDGE),
                Map.entry("ClientTransportPlugin", "obfs4,webtunnel exec pluggable_transports/lyrebird"),
                Map.entry("ClientTransportPlugin", "snowflake exec pluggable_transports/lyrebird"));
    }

    // The sandbox lets Tor start these programs, and the transports decide its network.
    @Test
    void findsTheTransportsAndTheProgramOfEachPluginEntry() {
        String conjureBridge = "conjure 143.110.214.222:80 0123456789ABCDEF0123456789ABCDEF01234567";
        BridgeConfig bridgeConfig = BridgeConfig.custom(List.of(SNOWFLAKE_BRIDGE, OBFS4_BRIDGE, WEBTUNNEL_BRIDGE,
                VANILLA_BRIDGE, conjureBridge));

        List<Map.Entry<String, String>> entries = BridgeTorrcEntries.create(bridgeConfig, config,
                program -> Optional.of(program.equals("conjure-client") ? "/usr/bin/" + program :
                        "pluggable_transports/" + program));

        assertThat(BridgeTorrcEntries.findClientTransportPlugins(entries)).containsExactly(
                new BridgeTorrcEntries.ClientTransportPlugin(List.of("conjure"), "/usr/bin/conjure-client"),
                new BridgeTorrcEntries.ClientTransportPlugin(List.of("obfs4", "webtunnel"),
                        "pluggable_transports/lyrebird"),
                new BridgeTorrcEntries.ClientTransportPlugin(List.of("snowflake"), "pluggable_transports/lyrebird"));
        assertThat(BridgeTorrcEntries.findClientTransportPlugins(BridgeTorrcEntries.create(
                BridgeConfig.custom(List.of(VANILLA_BRIDGE)), config, program -> Optional.empty()))).isEmpty();
    }

    @Test
    void theArgumentsOfAProgramFollowItsPath() {
        String conjureBridge = "conjure 143.110.214.222:80 0123456789ABCDEF0123456789ABCDEF01234567";

        List<Map.Entry<String, String>> entries = BridgeTorrcEntries.create(BridgeConfig.custom(List.of(conjureBridge)),
                config, program -> Optional.of("/usr/bin/" + program));

        assertThat(entries).contains(Map.entry("ClientTransportPlugin",
                "conjure exec /usr/bin/conjure-client -registerURL https://registration.refraction.network/api"));
    }

    @Test
    void bridgesWithoutTransportNeedNoProgram() {
        List<Map.Entry<String, String>> entries = BridgeTorrcEntries.create(
                BridgeConfig.custom(List.of(VANILLA_BRIDGE)), config, program -> Optional.empty());

        assertThat(entries).containsExactly(Map.entry("UseBridges", "1"), Map.entry("Bridge", VANILLA_BRIDGE));
    }

    @Test
    void aMissingProgramStopsTheStart() {
        assertThatThrownBy(() -> BridgeTorrcEntries.create(BridgeConfig.builtIn("snowflake"), config,
                program -> Optional.empty()))
                .isInstanceOf(BridgesUnavailableException.class)
                .hasMessageContaining("lyrebird");
    }

    @Test
    void aTransportWithoutProgramStopsTheStart() {
        String meekBridge = "meek 0.0.2.0:3 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/";

        assertThatThrownBy(() -> BridgeTorrcEntries.create(BridgeConfig.custom(List.of(meekBridge)), config,
                program -> Optional.of("pluggable_transports/" + program)))
                .isInstanceOf(BridgesUnavailableException.class)
                .hasMessageContaining("meek");
    }

    @Test
    void unknownBuiltInBridgesStopTheStart() {
        assertThatThrownBy(() -> BridgeTorrcEntries.create(BridgeConfig.builtIn("obfs3"), config,
                program -> Optional.of("pluggable_transports/" + program)))
                .isInstanceOf(BridgesUnavailableException.class)
                .hasMessageContaining("meek, obfs4, snowflake");
    }

    @Test
    void builtInBridgesOfATypeWithoutBridgesStopTheStart() {
        // UseBridges 1 without a Bridge entry would fail in Tor with its own message
        PluggableTransportConfig configWithEmptyType = PluggableTransportConfig.parse("""
                {"pluggableTransports": {}, "bridges": {"obfs4": [], "snowflake": ["snowflake 192.0.2.3:80 \
                0123456789ABCDEF0123456789ABCDEF01234567"]}}
                """);

        assertThatThrownBy(() -> BridgeTorrcEntries.create(BridgeConfig.builtIn("obfs4"), configWithEmptyType,
                program -> Optional.of("pluggable_transports/" + program)))
                .isInstanceOf(BridgesUnavailableException.class)
                .hasMessageContaining("obfs4")
                .hasMessageContaining("snowflake");
    }

    @Test
    void aBridgeLineMustStartWithATransportOrAnAddress() {
        assertThat(BridgeTorrcEntries.findTransport(" obfs4 192.0.2.1:443")).contains("obfs4");
        assertThat(BridgeTorrcEntries.findTransport("[2001:db8::1]:443")).isEmpty();
        assertThatThrownBy(() -> BridgeTorrcEntries.findTransport("obfs-4 192.0.2.1:443"))
                .isInstanceOf(BridgesUnavailableException.class);
    }
}
