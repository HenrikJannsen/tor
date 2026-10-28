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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the peers on the public Tor network, as the CI job of netlayer runs its peer message test on every platform. On
 * macOS and Windows this is the only test which starts the bundled Tor through TorService. It needs the internet, so it
 * runs only with the Gradle property tor.publicNetworkTests=true.
 */
@EnabledIfSystemProperty(named = "tor.publicNetworkTests", matches = "true")
@Timeout(value = 20, unit = TimeUnit.MINUTES)
class PublicTorNetworkOnionServiceTest extends OnionServiceIntegrationTests {
    // The test starts five Tors from this host within minutes. Once, the third one stayed at "Loading relay
    // descriptors" (53 %) for two minutes and did not bootstrap within 3 minutes.
    private static final int BOOTSTRAP_TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(5);
    private static final int HS_UPLOAD_TIMEOUT_MS = (int) TimeUnit.MINUTES.toMillis(3);

    @Override
    TorTransportConfig createTransportConfig(Path torDir) {
        return createTransportConfig(torDir, TorSandboxConfig.DISABLED);
    }

    private static TorTransportConfig createTransportConfig(Path torDir, TorSandboxConfig sandboxConfig) {
        return new TorTransportConfig(torDir, BOOTSTRAP_TIMEOUT_MS, HS_UPLOAD_TIMEOUT_MS, false, Set.of(), Map.of(),
                false, BridgeConfig.NONE, sandboxConfig);
    }

    // netlayer tries 12 times, 5 s apart
    @Override
    Duration getConnectTimeout() {
        return Duration.ofMinutes(3);
    }

    /**
     * In the sandbox, as Bisq 2 runs Tor by default, Tor connects out through the egress broker of sandy and reaches
     * the onion service of the peer through a forwarded port. The egress broker refuses the addresses of this host,
     * so a private network on this host cannot test it.
     */
    @Test
    void aPeerWhoseTorRunsInTheSandboxExchangesMessagesWithAPeer() throws InterruptedException {
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        TorSandboxConfig sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "");
        try (OnionPeer sandra = OnionPeer.start("sandra", createTransportConfig(tempDir.resolve("sandra"),
                sandboxConfig), getConnectTimeout())) {
            assertThat(sandra.getTorService().getSandboxStatus().isSandboxed()).isTrue();
            assertThat(sandra.send(alice, "hello alice")).isEqualTo(AckServer.ackOf("alice", "hello alice"));
            assertThat(alice.send(sandra, "hello sandra")).isEqualTo(AckServer.ackOf("sandra", "hello sandra"));
        }
    }
}
