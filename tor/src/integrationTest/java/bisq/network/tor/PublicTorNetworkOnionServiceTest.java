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

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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
        return new TorTransportConfig(torDir, BOOTSTRAP_TIMEOUT_MS, HS_UPLOAD_TIMEOUT_MS, false, Set.of(), Map.of(),
                false);
    }

    // netlayer tries 12 times, 5 s apart
    @Override
    Duration getConnectTimeout() {
        return Duration.ofMinutes(3);
    }
}
