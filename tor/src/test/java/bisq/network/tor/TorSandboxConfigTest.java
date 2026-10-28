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
        // sandy has no published release which a build could package.
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
    void onlyThePluggableTransportsLetTorStartProcesses() {
        assertThat(TorrcClientConfigFactory.startsChildProcesses(List.of("UseBridges", "Bridge",
                "ClientTransportPlugin"))).isTrue();
        assertThat(TorrcClientConfigFactory.startsChildProcesses(List.of("servertransportplugin"))).isTrue();
        // A bridge without transport needs no process.
        assertThat(TorrcClientConfigFactory.startsChildProcesses(List.of("UseBridges", "Bridge"))).isFalse();
        // Exact names: an abbreviation fails the sandboxed start instead of turning the sandbox off.
        assertThat(TorrcClientConfigFactory.startsChildProcesses(List.of("ClientTransportPlug"))).isFalse();
    }
}
