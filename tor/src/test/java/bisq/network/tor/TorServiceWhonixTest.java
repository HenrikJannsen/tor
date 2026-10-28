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

import bisq.network.tor.controller.FakeTorControlServer;
import bisq.network.tor.controller.TestKeys;
import bisq.network.tor.controller.TorCommandFilteredException;
import bisq.network.tor.onionservice.OnionServiceKey;
import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Bisq on a Whonix-Workstation, against a control port which answers like onion-grater with the profile 40_bisq of
 * Whonix (onion-grater 83b58299, profile of 2026-06-28). onion-grater accepts every AUTHENTICATE, filters every command
 * which no rule allows, answers the bootstrap phase and the SOCKS listener itself, and accepts ADD_ONION only with a
 * bare local port as target, which it rewrites to the address of the Workstation.
 */
@Timeout(30)
class TorServiceWhonixTest {
    // The ADD_ONION rules of 40_bisq.yml. onion-grater matches the whole argument string.
    private static final List<Pattern> ADD_ONION_RULES = List.of(
            Pattern.compile("NEW:(\\S+) Port=9999,(\\S+)"),
            Pattern.compile("(\\S+) Port=(\\S+),(\\S+)"),
            Pattern.compile("(\\S+):(\\S+) Port=9999,(\\S+)"));
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
    private FakeTorControlServer onionGrater;
    private TorService torService;

    @AfterEach
    void tearDown() throws Exception {
        if (torService != null) {
            torService.shutdown().join();
        }
        if (onionGrater != null) {
            onionGrater.close();
        }
    }

    @Test
    void bisqPublishesItsOnionServiceThroughOnionGrater() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        onionGrater = new FakeTorControlServer(command -> onionGraterReply(command, true, serviceId, OLD_UPLOAD_EVENTS));
        // The cookie file of a Workstation holds a dummy value, and onion-grater filters AUTHCHALLENGE.
        Path dummyCookie = Files.write(torDir.resolve("control.authcookie"), new byte[32]);
        Files.writeString(torDir.resolve("external_tor.config"), "CookieAuthentication 1\nCookieAuthFile " +
                dummyCookie + "\nControlPort 127.0.0.1:" + onionGrater.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES, true);

        assertThat(torService.initialize().join()).isTrue();
        ServerSocket serverSocket = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey).join();

        try (serverSocket) {
            // The Tor of the Gateway connects to the address of the Workstation.
            assertThat(serverSocket.getInetAddress().isAnyLocalAddress()).isTrue();
        }
        // A server which the application publishes itself, such as the API of Bisq 2, has to listen there as well.
        assertThat(torService.getOnionServiceBindAddress().isAnyLocalAddress()).isTrue();
        assertThat(onionGrater.getCommands())
                .noneMatch(command -> command.startsWith("AUTHCHALLENGE"))
                .noneMatch(command -> command.startsWith("TAKEOWNERSHIP") || command.startsWith("SETCONF") ||
                        command.startsWith("RESETCONF"))
                .anyMatch(command -> command.startsWith("ADD_ONION ED25519-V3:") &&
                        command.endsWith(" Port=9999," + serverSocket.getLocalPort()));
        assertThat(torService.getTorVersion()).contains("0.4.8.16");
        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.EXTERNAL_TOR);
    }

    @Test
    void aGatewayWithoutTheProfileOfBisqStopsThePublicationWithTheFilteredCommand() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        onionGrater = new FakeTorControlServer(command -> onionGraterReply(command, false, serviceId, OLD_UPLOAD_EVENTS));
        Files.writeString(torDir.resolve("external_tor.config"), "ControlPort 127.0.0.1:" + onionGrater.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES, true);
        torService.initialize().join();

        // TorService passes its own Whonix flag, so the advice does not depend on the system which runs the test.
        assertThatThrownBy(() -> torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey).join())
                .hasRootCauseInstanceOf(TorCommandFilteredException.class)
                .rootCause()
                .hasMessageContaining("ADD_ONION")
                .hasMessageContaining("sudo onion-grater-add 40_bisq")
                .hasMessageNotContaining(serviceId);
    }

    // The Gateway has the markers of Whonix too. Taken for a Workstation, Bisq would look for the control port which the
    // Workstation forwards to the Gateway.
    @Test
    void onAWhonixGatewayBisqDoesNotStart() {
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES, true, true);

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("does not run on a Whonix-Gateway")
                .hasMessageContaining("Run Bisq on a Whonix-Workstation")
                .hasNoCause();
        assertThat(torDir.resolve("external_tor.config")).doesNotExist();
    }

    // Since September 2024 onion-grater passes UPLOAD as Tor sends it (five fields), and the publication completes at the
    // UPLOADED with the redacted HSDir which every profile delivers.
    @Test
    void bisqPublishesItsOnionServiceWithTheUploadEventsOfCurrentProfiles() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        onionGrater = new FakeTorControlServer(command -> onionGraterReply(command, true, serviceId, id ->
                "650 HS_DESC UPLOAD " + id + " UNKNOWN $0123456789ABCDEF0123456789ABCDEF01234567~relay " +
                        "descriptorId HSDIR_INDEX=index\r\n" +
                        "650 HS_DESC UPLOADED " + id + " UNKNOWN redacted\r\n"));
        Files.writeString(torDir.resolve("external_tor.config"), "ControlPort 127.0.0.1:" + onionGrater.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES, true);
        torService.initialize().join();

        try (ServerSocket serverSocket = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey)
                .join()) {
            assertThat(serverSocket.getInetAddress().isAnyLocalAddress()).isTrue();
        }
    }

    // A Gateway whose profiles filter a command of the start: the filtered command gives the advice, once.
    @Test
    void aFilteredCommandOfTheStartGivesTheAdviceForOnionGraterOnce() throws Exception {
        onionGrater = new FakeTorControlServer(command -> command.equals("GETINFO net/listeners/socks") ?
                "510 Command filtered\r\n" :
                onionGraterReply(command, true, "unused", OLD_UPLOAD_EVENTS));
        Files.writeString(torDir.resolve("external_tor.config"), "ControlPort 127.0.0.1:" + onionGrater.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES, true);

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(ExternalTorUnavailableException.class)
                .hasMessageContaining("GETINFO")
                .satisfies(e -> assertThat(e.getMessage().split("onion-grater-add", -1)).hasSize(2));
    }

    // The upload events as the profiles before September 2024 deliver them
    private static final Function<String, String> OLD_UPLOAD_EVENTS = serviceId ->
            "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN redacted redacted\r\n" +
                    "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted\r\n";

    // onion-grater with the default profile of Whonix, and with or without the profile 40_bisq
    private static String onionGraterReply(String command,
                                           boolean hasBisqProfile,
                                           String serviceId,
                                           Function<String, String> uploadEvents) {
        if (command.startsWith("AUTHENTICATE")) {
            return "250 OK\r\n";
        }
        if (command.equals("GETINFO status/bootstrap-phase") && hasBisqProfile) {
            return "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO version")) {
            return "250-version=0.4.8.16\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO net/listeners/socks")) {
            return "250-net/listeners/socks=\"127.0.0.1:9150\"\r\n250 OK\r\n";
        }
        if (command.equals("SETEVENTS HS_DESC") || command.equals("SETEVENTS")) {
            return "250 OK\r\n";
        }
        if (command.startsWith("ADD_ONION ") && hasBisqProfile) {
            String arguments = command.substring("ADD_ONION ".length());
            Matcher matcher = ADD_ONION_RULES.stream()
                    .map(rule -> rule.matcher(arguments))
                    .filter(Matcher::matches)
                    .findFirst()
                    .orElse(null);
            if (matcher == null) {
                return "510 Command filtered\r\n";
            }
            String target = matcher.group(matcher.groupCount());
            if (!target.matches("\\d+")) {
                // onion-grater puts the address of the Workstation before the target, so Tor gets an invalid one.
                return "512 Cannot parse target address\r\n";
            }
            return "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" + uploadEvents.apply(serviceId);
        }
        if ((command.startsWith("DEL_ONION ") || command.startsWith("HSFETCH ")) && hasBisqProfile) {
            return "250 OK\r\n";
        }
        return "510 Command filtered\r\n";
    }

    private TorTransportConfig createTransportConfig() {
        // If the test failed and TorService started its own Tor, Tor would send its connections to a closed local
        // port instead of the Tor network.
        return new TorTransportConfig(torDir, 1000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
    }
}
