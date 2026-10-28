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

import bisq.network.tor.sandbox.PluggableTransportsNotAllowedException;
import bisq.network.tor.sandbox.SandboxUnavailableException;
import bisq.network.tor.sandbox.SandboxedTransports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An application can tell a refusal of the pluggable transports of the bridges from a sandbox which cannot run, so
 * that it can tell the user how to allow them in its own terms, or let the user choose other bridges.
 */
class TorServiceSandboxRefusalTest {
    private static final String OPT_OUT_HINT = "Start Bisq with the option --useTorSandbox=false.";
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
    void bridgesWithTransportsWhichTheSandboxDoesNotAllowAreRefusedWithTheirNames() {
        TorSandboxConfig sandboxConfig = new TorSandboxConfig(true, true, false, 1, "bisq1", OPT_OUT_HINT);
        TorService torService = createTorService(Map.of(), sandboxConfig);
        var transports = new SandboxedTransports(Set.of("snowflake", "obfs4"),
                List.of(torDir.resolve("bin").resolve("lyrebird").toAbsolutePath(),
                        torDir.resolve("bin").resolve("snowflake-client").toAbsolutePath()));

        assertThatThrownBy(() ->
                torService.refuseWhatTheSandboxCannotRun(sandboxConfig, BridgeConfig.builtIn("obfs4"), transports))
                .isInstanceOfSatisfying(PluggableTransportsNotAllowedException.class, e ->
                        assertThat(e.getTransportNames()).containsExactly("obfs4", "snowflake"))
                .hasMessageContaining("obfs4, snowflake")
                .hasMessageContaining(OPT_OUT_HINT);
    }

    @Test
    void otherRefusalsAreNoRefusalOfTheTransports() {
        TorSandboxConfig sandboxConfig = new TorSandboxConfig(true, true, true, 1, "bisq1", OPT_OUT_HINT);
        TorService torService = createTorService(Map.of("Socks5Proxy", "127.0.0.1:9050"), sandboxConfig);

        assertThatThrownBy(() -> torService.refuseWhatTheSandboxCannotRun(sandboxConfig, BridgeConfig.NONE,
                SandboxedTransports.NONE))
                .isInstanceOf(SandboxUnavailableException.class)
                .isNotInstanceOf(PluggableTransportsNotAllowedException.class);
    }

    private TorService createTorService(Map<String, String> torrcOverrides, TorSandboxConfig sandboxConfig) {
        var transportConfig = new TorTransportConfig(torDir, 1000, 1000, false, Set.of(), torrcOverrides, false,
                BridgeConfig.NONE, sandboxConfig);
        return new TorService(transportConfig, PLATFORM_SERVICES, false);
    }
}
