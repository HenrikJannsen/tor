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
import bisq.network.tor.onionservice.OnionServiceKey;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Users share their log files. In Bisq 2 each user profile has its own onion service, so a log which names the onion
 * services at the level users share would link the profiles of a user. The test publishes onion services against a
 * local fake control port and checks the logged lines of the library.
 */
@Isolated("Captures the log of the library")
@Timeout(30)
class TorServiceLoggingTest {
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

    private final Logger libraryLogger = (Logger) LoggerFactory.getLogger("bisq.network.tor");
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    @TempDir
    Path torDir;
    private FakeTorControlServer fakeTor;
    private TorService torService;

    @BeforeEach
    void setUp() {
        appender.start();
        libraryLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() throws Exception {
        libraryLogger.detachAppender(appender);
        if (torService != null) {
            torService.shutdown().join();
        }
        if (fakeTor != null) {
            fakeTor.close();
        }
    }

    @Test
    void thePublicationWithAServerSocketLogsTheOnionAddressAtDebugLevelOnly() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = serviceIdOf(onionServiceKey);
        startWithFakeTor(serviceId);

        try (ServerSocket serverSocket = torService.publishOnionServiceAndCreateServerSocket(9999, onionServiceKey).join()) {
            assertThat(serverSocket.isBound()).isTrue();
        }

        assertNoOnionAddressAboveDebugLevel(serviceId);
    }

    @Test
    void thePublicationForALocalPortLogsTheOnionAddressAtDebugLevelOnly() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = serviceIdOf(onionServiceKey);
        startWithFakeTor(serviceId);

        assertThat(torService.publishOnionService(8080, 9999, onionServiceKey).join())
                .isEqualTo(onionServiceKey.getOnionAddress());

        assertNoOnionAddressAboveDebugLevel(serviceId);
    }

    @Test
    void aFailedPublicationLogsTheOnionAddressesAtDebugLevelOnly() throws Exception {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = serviceIdOf(onionServiceKey);
        // Tor reports the onion address of another key, which fails the publication with both addresses at hand
        String otherServiceId = serviceIdOf(TestKeys.randomOnionServiceKey());
        startWithFakeTor(otherServiceId);

        assertThat(torService.publishOnionService(8080, 9999, onionServiceKey)).isCompletedExceptionally();

        assertThat(textsAboveDebugLevel())
                .noneMatch(text -> text.contains(serviceId) || text.contains(otherServiceId))
                .anyMatch(text -> text.startsWith("Can't create onion service"));
        assertThat(appender.list)
                .filteredOn(event -> event.getLevel() == Level.DEBUG)
                .anyMatch(event -> event.getFormattedMessage().contains(serviceId));
    }

    private void assertNoOnionAddressAboveDebugLevel(String serviceId) {
        assertThat(textsAboveDebugLevel())
                .noneMatch(text -> text.contains(serviceId))
                .anyMatch(text -> text.contains("Tor onion service ready"));
        assertThat(appender.list)
                .filteredOn(event -> event.getLevel() == Level.DEBUG)
                .anyMatch(event -> event.getFormattedMessage().contains(serviceId));
    }

    // The messages of the logged lines above debug level, with the messages of their exceptions and causes
    private List<String> textsAboveDebugLevel() {
        return appender.list.stream()
                .filter(event -> event.getLevel().isGreaterOrEqual(Level.INFO))
                .map(TorServiceLoggingTest::textOf)
                .collect(Collectors.toList());
    }

    private static String textOf(ILoggingEvent event) {
        StringBuilder text = new StringBuilder(event.getFormattedMessage());
        for (IThrowableProxy throwable = event.getThrowableProxy(); throwable != null; throwable = throwable.getCause()) {
            text.append('\n').append(throwable.getMessage());
        }
        return text.toString();
    }

    // reportedServiceId: the service ID which Tor reports for every ADD_ONION
    private void startWithFakeTor(String reportedServiceId) throws IOException {
        fakeTor = new FakeTorControlServer(command -> reply(command, reportedServiceId));
        Files.writeString(torDir.resolve("external_tor.config"), "UseExternalTor 1\nCookieAuthentication 0\n" +
                "ControlPort 127.0.0.1:" + fakeTor.getPort());
        torService = new TorService(createTransportConfig(), PLATFORM_SERVICES);
        assertThat(torService.initialize().join()).isTrue();
    }

    private static String serviceIdOf(OnionServiceKey onionServiceKey) {
        return onionServiceKey.getOnionAddress().replace(".onion", "");
    }

    // A Tor which has bootstrapped and publishes the onion service at once
    private static String reply(String command, String serviceId) {
        if (command.startsWith("AUTHENTICATE") || command.startsWith("SETEVENTS") || command.startsWith("DEL_ONION")) {
            return "250 OK\r\n";
        }
        if (command.equals("GETINFO status/bootstrap-phase")) {
            return "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO version")) {
            return "250-version=0.4.8.16\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO net/listeners/socks")) {
            return "250-net/listeners/socks=\"127.0.0.1:9150\"\r\n250 OK\r\n";
        }
        if (command.startsWith("ADD_ONION ")) {
            return "250-ServiceID=" + serviceId + "\r\n250 OK\r\n" +
                    "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN redacted redacted\r\n" +
                    "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted\r\n";
        }
        return "552 Unrecognized command\r\n";
    }

    private TorTransportConfig createTransportConfig() {
        // If the test failed and TorService started its own Tor, Tor would send its connections to a closed local
        // port instead of the Tor network.
        return new TorTransportConfig(torDir, 1000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
    }
}
