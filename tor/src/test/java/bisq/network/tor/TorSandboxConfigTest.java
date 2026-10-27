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

import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorSandboxConfigTest {
    @Test
    void theSandboxIsOffUnlessTheConfigurationTurnsItOn() {
        // sandy has no public release which a build could download and package.
        TorSandboxConfig missing = TorSandboxConfig.from(ConfigFactory.parseString("useExternalTor = false"));
        TorSandboxConfig enabled = TorSandboxConfig.from(ConfigFactory.parseString("sandbox { enabled = true }"));

        assertThat(missing.isEnabled()).isFalse();
        assertThat(enabled.isEnabled()).isTrue();
        assertThat(enabled.getApplicationId()).isEqualTo("bisq2");
        assertThat(enabled.getOptOutHint()).contains(TorSandboxConfig.BISQ2_CONFIG_PATH + ".enabled=false");
    }

    @Test
    void theOnionServicePortsAreForwardedByDefault() {
        // In its sandbox Tor has a network of its own on every platform, so it reaches Bisq only through them.
        TorSandboxConfig config = TorSandboxConfig.from(ConfigFactory.parseString("sandbox { enabled = true }"));
        TorSandboxConfig direct = TorSandboxConfig.from(ConfigFactory.parseString(
                "sandbox { enabled = true, forwardOnionServicePorts = false, onionServicePortPoolSize = 64 }"));

        assertThat(config.isForwardOnionServicePorts()).isTrue();
        assertThat(config.getOnionServicePortPoolSize()).isEqualTo(32);
        assertThat(TorSandboxConfig.DISABLED.isForwardOnionServicePorts()).isTrue();
        assertThat(direct.isForwardOnionServicePorts()).isFalse();
        assertThat(direct.getOnionServicePortPoolSize()).isEqualTo(64);
        assertThatThrownBy(() -> TorSandboxConfig.from(ConfigFactory.parseString(
                "sandbox { onionServicePortPoolSize = 0 }")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theSandboxAllowsNoPluggableTransportsByDefault() {
        TorSandboxConfig config = TorSandboxConfig.from(ConfigFactory.parseString("sandbox { enabled = true }"));
        TorSandboxConfig allowing = TorSandboxConfig.from(ConfigFactory.parseString(
                "sandbox { enabled = true, allowPluggableTransports = true }"));

        assertThat(config.isAllowPluggableTransports()).isFalse();
        assertThat(TorSandboxConfig.DISABLED.isAllowPluggableTransports()).isFalse();
        assertThat(allowing.isAllowPluggableTransports()).isTrue();
    }

    /**
     * In its sandbox Tor connects out only through the egress broker of sandy, so a torrc override of a proxy option
     * refuses the sandboxed start. Tor reads an abbreviation and any case as the option.
     */
    @Test
    void findsTheProxyOptionsOfTheTorrcOverrides() {
        assertThat(TorrcClientConfigFactory.proxyKeys(List.of("HTTPSProxy", "socks5proxy", "Socks4Prox",
                "TCPProxy", "SafeSocks", "UseBridges", "Socks5ProxyUsername")))
                .containsExactly("HTTPSProxy", "Socks4Prox", "Socks5ProxyUsername", "TCPProxy", "socks5proxy");
        assertThat(TorrcClientConfigFactory.proxyKeys(List.of("SocksPort", "SafeSocks", "Log"))).isEmpty();
    }

    @Test
    void findsTheGeoIpFileOptionsOfTheTorrcOverrides() {
        assertThat(TorrcClientConfigFactory.geoIpFileKeys(List.of("GeoIPFile", "geoipv6file", "GeoIPv6",
                "GeoIPExcludeUnknown", "ExcludeNodes")))
                .containsExactly("GeoIPFile", "GeoIPv6", "geoipv6file");
    }

    @Test
    void onlyThePluggableTransportsLetTorStartProcesses() {
        assertThat(TorrcClientConfigFactory.processStartingKeys(List.of("UseBridges", "Bridge",
                "ClientTransportPlugin"), false)).containsExactly("ClientTransportPlugin");
        assertThat(TorrcClientConfigFactory.processStartingKeys(List.of("servertransportplugin"), false))
                .containsExactly("servertransportplugin");
        // A bridge without transport needs no process.
        assertThat(TorrcClientConfigFactory.processStartingKeys(List.of("UseBridges", "Bridge"), false)).isEmpty();
        // Tor accepts abbreviations of option names.
        assertThat(TorrcClientConfigFactory.processStartingKeys(List.of("ClientTransportPlug", "ServerTransportPl",
                "ServerTransportOptions"), false)).containsExactly("ClientTransportPlug", "ServerTransportPl");
    }

    // With the bridges of the configuration, the overrides of the bridge keys are ignored, but ServerTransportPlugin
    // stays in the torrc.
    @Test
    void withBridgesOnlyServerTransportPluginOverridesStartProcesses() {
        assertThat(TorrcClientConfigFactory.processStartingKeys(List.of("ClientTransportPlugin",
                "ClientTransportPlug", "ServerTransportPlugin"), true)).containsExactly("ServerTransportPlugin");
    }
}
