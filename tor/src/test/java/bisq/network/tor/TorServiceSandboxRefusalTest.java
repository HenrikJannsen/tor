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

import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.process.TorStartupFailedException;
import bisq.network.tor.sandbox.PluggableTransportsNotAllowedException;
import bisq.network.tor.sandbox.SandboxUnavailableException;
import bisq.network.tor.sandbox.SandboxedTransports;
import bisq.network.tor.sandbox.Sandy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
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

    // The sandbox does not grant the file, so Tor would run without country data and its country selectors would
    // match no relay.
    @Test
    void aGeoIpFileOfTheTorrcOverridesIsRefused() {
        TorSandboxConfig sandboxConfig = new TorSandboxConfig(true, true, false, 1, "bisq1", OPT_OUT_HINT);
        TorService torService = createTorService(Map.of("GeoIPFile", "/home/user/geoip",
                "ExcludeNodes", "{us}"), sandboxConfig);

        assertThatThrownBy(() -> torService.refuseWhatTheSandboxCannotRun(sandboxConfig, BridgeConfig.NONE,
                SandboxedTransports.NONE))
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("GeoIPFile")
                .hasMessageContaining(OPT_OUT_HINT);
    }

    // The authorities of a test network listen on 127.0.0.1, which the egress broker of sandy does not reach.
    @Test
    void aTestNetworkIsRefusedInALevelWithTheEgressBroker() {
        DirectoryAuthority authority = DirectoryAuthority.builder()
                .nickname("A0")
                .orPort(19001)
                .dirPort(19002)
                .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                .relayFingerprint("89ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .build();
        var base = new Sandy.Level("base", Set.of(Sandy.EGRESS_BROKERED, Sandy.IP_NETWORK_PRIVATE));
        var hostNetwork = new Sandy.Level("host-network", Set.of(Sandy.ENDS_WITH_PARENT));

        assertThatThrownBy(() -> TorService.refuseDestinationsOutsideTheEgress(base, Set.of(authority), List.of(),
                OPT_OUT_HINT))
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("directory authorities of the test network")
                .hasMessageContaining("level base")
                .hasMessageContaining(OPT_OUT_HINT);
        // With the network of the host Tor reaches 127.0.0.1, and without a test network there is nothing to refuse.
        TorService.refuseDestinationsOutsideTheEgress(hostNetwork, Set.of(authority), List.of(), OPT_OUT_HINT);
        TorService.refuseDestinationsOutsideTheEgress(base, Set.of(), List.of(), OPT_OUT_HINT);
    }

    // The egress broker of sandy reaches public addresses only, so Tor could reach none of these bridges.
    @Test
    void bridgesOnlyOnAddressesOfThisHostOrTheLocalNetworkAreRefusedInALevelWithTheEgressBroker() {
        var base = new Sandy.Level("base", Set.of(Sandy.EGRESS_BROKERED, Sandy.IP_NETWORK_PRIVATE));
        List<Map.Entry<String, String>> localBridges = List.of(Map.entry("UseBridges", "1"),
                Map.entry("Bridge", "127.0.0.1:9001 0123456789ABCDEF0123456789ABCDEF01234567"),
                Map.entry("Bridge", "obfs4 192.168.1.20:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=x"));

        assertThatThrownBy(() -> TorService.refuseDestinationsOutsideTheEgress(base, Set.of(), localBridges,
                OPT_OUT_HINT))
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("bridges of the configuration are on addresses of this host or of the local")
                .hasMessageNotContaining("192.168.1.20")
                .hasMessageContaining(OPT_OUT_HINT);
    }

    // Tor uses the bridges it reaches; one on a public address is enough.
    @Test
    void bridgesWithOneOnAPublicAddressStartInEveryLevel() {
        var base = new Sandy.Level("base", Set.of(Sandy.EGRESS_BROKERED, Sandy.IP_NETWORK_PRIVATE));
        var hostNetwork = new Sandy.Level("host-network", Set.of(Sandy.ENDS_WITH_PARENT));
        List<Map.Entry<String, String>> localBridges = List.of(
                Map.entry("Bridge", "10.0.0.2:9001 0123456789ABCDEF0123456789ABCDEF01234567"));
        List<Map.Entry<String, String>> mixedBridges = List.of(
                Map.entry("Bridge", "10.0.0.2:9001 0123456789ABCDEF0123456789ABCDEF01234567"),
                Map.entry("Bridge", "obfs4 [2001:4860:4860::8888]:443 0123456789ABCDEF0123456789ABCDEF01234567"));

        TorService.refuseDestinationsOutsideTheEgress(base, Set.of(), mixedBridges, OPT_OUT_HINT);
        TorService.refuseDestinationsOutsideTheEgress(hostNetwork, Set.of(), localBridges, OPT_OUT_HINT);
    }

    // Another process can take a port of the policy between the reservation of the ports and sandy.
    @Test
    void aStartWhichSandyRefusesIsTriedOnceMore() {
        AtomicInteger starts = new AtomicInteger();

        TorService.retryOnceAfterARefusalOfSandy(() -> {
            if (starts.incrementAndGet() == 1) {
                throw new TorService.SandyRefusalException("cannot listen on 127.0.0.1:12345", OPT_OUT_HINT);
            }
        });

        assertThat(starts).hasValue(2);
    }

    @Test
    void aSecondRefusalOfSandyFailsTheStartWithTheAdvice() {
        AtomicInteger starts = new AtomicInteger();

        assertThatThrownBy(() -> TorService.retryOnceAfterARefusalOfSandy(() -> {
            starts.incrementAndGet();
            throw new TorService.SandyRefusalException("cannot listen on 127.0.0.1:12345", OPT_OUT_HINT);
        }))
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("cannot listen on 127.0.0.1:12345")
                .hasMessageContaining(OPT_OUT_HINT);
        assertThat(starts).hasValue(2);
    }

    // A system which enforces no level, a configuration which the sandbox refuses and a failed start of Tor stay.
    @Test
    void otherFailuresOfTheStartAreNotTriedAgain() {
        for (RuntimeException failure : List.of(new SandboxUnavailableException("no level", OPT_OUT_HINT),
                new TorStartupFailedException("Tor exited"))) {
            AtomicInteger starts = new AtomicInteger();

            assertThatThrownBy(() -> TorService.retryOnceAfterARefusalOfSandy(() -> {
                starts.incrementAndGet();
                throw failure;
            })).isSameAs(failure);
            assertThat(starts).hasValue(1);
        }
    }

    // sandy check exits with 125 when it cannot tell now, for example for a port which another process holds.
    @Test
    void onlyACheckWhichCannotTellNowCanPass() {
        var undecided = new Sandy.CheckResult(Sandy.EXIT_STATUS_NOT_STARTED, Optional.empty(),
                "sandy: cannot listen on 127.0.0.1:12345");
        var notEnforceable = new Sandy.CheckResult(1, Optional.empty(), "level base: signals-isolated (unavailable)");

        assertThat(TorService.refusalOfCheck(undecided, OPT_OUT_HINT))
                .isInstanceOf(TorService.SandyRefusalException.class)
                .hasMessageContaining("A later start may succeed")
                .hasMessageContaining(OPT_OUT_HINT);
        assertThat(TorService.refusalOfCheck(notEnforceable, OPT_OUT_HINT))
                .isNotInstanceOf(TorService.SandyRefusalException.class)
                .hasMessageContaining("cannot enforce any level")
                .hasMessageContaining(OPT_OUT_HINT);
    }

    private TorService createTorService(Map<String, String> torrcOverrides, TorSandboxConfig sandboxConfig) {
        var transportConfig = new TorTransportConfig(torDir, 1000, 1000, false, Set.of(), torrcOverrides, false,
                BridgeConfig.NONE, sandboxConfig);
        return new TorService(transportConfig, PLATFORM_SERVICES, false);
    }
}
