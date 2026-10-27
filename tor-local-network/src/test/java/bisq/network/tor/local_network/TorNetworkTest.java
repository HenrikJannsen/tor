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

package bisq.network.tor.local_network;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorNetworkTest {
    private final Path bundleDirPath = Path.of("network", "tor_binary");

    @Test
    void linuxStartsTheTorOfTheSystem() {
        // The Linux bundle has only the pluggable transports, like the bundle which TorService installs
        Path systemTorPath = Path.of("/usr/bin/tor");

        assertThat(TorNetwork.torBinaryPath(bundleDirPath, true, false, Optional.of(systemTorPath)))
                .isEqualTo(systemTorPath);
    }

    @Test
    void linuxWithoutATorInPathFailsBeforeAnyProcessStarts() {
        assertThatThrownBy(() -> TorNetwork.torBinaryPath(bundleDirPath, true, false, Optional.empty()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("PATH names no tor");
    }

    @Test
    void theOtherPlatformsStartTheBundledTor() {
        assertThat(TorNetwork.torBinaryPath(bundleDirPath, false, false, Optional.empty()))
                .isEqualTo(bundleDirPath.resolve("tor"));
        assertThat(TorNetwork.torBinaryPath(bundleDirPath, false, true, Optional.empty()))
                .isEqualTo(bundleDirPath.resolve("tor.exe"));
    }
}
