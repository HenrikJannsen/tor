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

import bisq.network.tor.process.TorDirectories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A torrc override which makes Tor start a program or load a library stops the start of the embedded Tor if it comes
 * from a configuration file which the application writes itself. From the command line or the code of the application
 * it is accepted.
 */
@Timeout(30)
class TorServiceConfigFileOverridesTest {
    private static final String HINT = "Pass them on the command line.";
    private static final PlatformServices PLATFORM_SERVICES = new PlatformServices() {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return Stream.empty();
        }

        @Override
        public boolean supportsPosixPermissions() {
            return false;
        }
    };

    @TempDir
    Path torDir;

    @Test
    void anOverrideOfAConfigFileWhichLoadsALibraryStopsTheStartBeforeTorIsInstalled() {
        TorService torService = new TorService(transportConfig(Map.of("AccelName", "engine", "Log", "notice stdout"),
                Set.of("AccelName", "Log")), PLATFORM_SERVICES, false, false);

        assertThatThrownBy(torService::initialize)
                .isInstanceOf(TorrcOverrideNotAllowedException.class)
                .hasMessageContaining("load a library: AccelName. " + HINT)
                .hasNoCause();
        TorDirectories torDirectories = new TorDirectories(torDir);
        assertThat(torDirectories.getTorrcPath()).doesNotExist();
        assertThat(torDirectories.getBinaryDirPath()).doesNotExist();
    }

    // Only the embedded Tor gets the torrc overrides. The external Tor of this test does not listen, so the start fails
    // at the connection, after the overrides passed.
    @Test
    void anExternalTorGetsNoOverridesSoTheyAreNotRefused() throws IOException {
        int closedPort;
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closedPort = serverSocket.getLocalPort();
        }
        Files.writeString(torDir.resolve("external_tor.config"),
                "UseExternalTor 1\nControlPort 127.0.0.1:" + closedPort);
        TorService torService = new TorService(transportConfig(Map.of("ClientTransportPlugin", "obfs4 exec /bin/true"),
                Set.of("ClientTransportPlugin")), PLATFORM_SERVICES, false, false);

        assertThatThrownBy(torService::initialize).isInstanceOf(ExternalTorUnavailableException.class);
    }

    @Test
    void everyOverrideWhichRunsCodeIsRefusedFromAConfigFileAlsoAbbreviated() {
        for (String key : Set.of("ClientTransportPlugin", "ServerTransportPlugin", "AccelName", "AccelDir", "Accel",
                "clienttransportplug")) {
            assertThatThrownBy(() -> TorService.refuseCodeRunningOverridesOfConfigFiles(
                    transportConfig(Map.of(key, "x"), Set.of(key))))
                    .isInstanceOf(TorrcOverrideNotAllowedException.class)
                    .hasMessageContaining(key);
        }
    }

    @Test
    void theSameOverridesFromTheCommandLineArePassedToTor() {
        Map<String, String> overrides = Map.of("AccelName", "engine", "ClientTransportPlugin", "obfs4 exec /bin/true");

        assertThatCode(() -> TorService.refuseCodeRunningOverridesOfConfigFiles(
                transportConfig(overrides, Set.of()))).doesNotThrowAnyException();
        // A key of the configuration file which the overrides do not hold changes nothing
        assertThatCode(() -> TorService.refuseCodeRunningOverridesOfConfigFiles(
                transportConfig(overrides, Set.of("AccelDir")))).doesNotThrowAnyException();
        assertThatCode(() -> TorService.refuseCodeRunningOverridesOfConfigFiles(new TorTransportConfig(torDir, 1000,
                1000, false, Set.of(), overrides, false))).doesNotThrowAnyException();
    }

    @Test
    void otherOverridesOfAConfigFileAreAccepted() {
        Map<String, String> overrides = Map.of("HardwareAccel", "1", "Log", "notice stdout", "UseBridges", "1");

        assertThatCode(() -> TorService.refuseCodeRunningOverridesOfConfigFiles(
                transportConfig(overrides, overrides.keySet()))).doesNotThrowAnyException();
    }

    private TorTransportConfig transportConfig(Map<String, String> torrcOverrides, Set<String> configFileKeys) {
        return new TorTransportConfig(torDir, 1000, 1000, false, Set.of(), torrcOverrides, false, BridgeConfig.NONE,
                TorSandboxConfig.DISABLED, new ConfigFileTorrcOverrides(configFileKeys, HINT));
    }
}
