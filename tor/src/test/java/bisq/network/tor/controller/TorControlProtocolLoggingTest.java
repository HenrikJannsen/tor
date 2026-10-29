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

package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.EventType;
import bisq.network.tor.controller.events.events.HsDescEvent;
import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.events.listener.HsDescEventListener;
import bisq.network.tor.onionservice.OnionServiceKey;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.google.common.io.BaseEncoding;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Users share their log files, so the Tor control commands and replies must not appear in the log with the secrets
 * which they carry. The test runs the protocol against a local fake control port and checks the logged lines.
 */
@Isolated("Captures the log of TorControlProtocol and TorControlReader")
@Timeout(10)
class TorControlProtocolLoggingTest {
    private final Logger protocolLogger = (Logger) LoggerFactory.getLogger(TorControlProtocol.class);
    private final Logger readerLogger = (Logger) LoggerFactory.getLogger(TorControlReader.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private ServerSocket serverSocket;
    private Thread serverThread;

    @BeforeEach
    void setUp() throws IOException {
        appender.start();
        // The control traffic is logged at debug level. The checks of the logged forms need it.
        protocolLogger.setLevel(Level.DEBUG);
        readerLogger.setLevel(Level.DEBUG);
        protocolLogger.addAppender(appender);
        readerLogger.addAppender(appender);
        // TorControlProtocol connects to 127.0.0.1
        serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
    }

    @AfterEach
    void tearDown() throws Exception {
        torControlProtocol.close();
        serverSocket.close();
        if (serverThread != null) {
            serverThread.join(5000);
        }
        protocolLogger.detachAppender(appender);
        readerLogger.detachAppender(appender);
        protocolLogger.setLevel(null);
        readerLogger.setLevel(null);
        appender.stop();
    }

    @Test
    void addOnionDoesNotLogThePrivateKey() {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String secretScalar = onionServiceKey.getBase64SecretScalar();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        startControlServer(command -> "250-ServiceID=" + serviceId + "\r\n250 OK\r\n");

        torControlProtocol.addOnion(onionServiceKey, 9999, 12345);

        List<String> messages = loggedMessages();
        assertThat(messages).noneMatch(message -> message.contains(secretScalar));
        assertThat(messages).contains("Send Tor control command: ADD_ONION ED25519-V3:[hidden] Port=9999,12345",
                "Received reply from Tor control server: 250-ServiceID=" + serviceId,
                "Received reply from Tor control server: 250 OK");
    }

    @Test
    void theControlTrafficIsLoggedAtDebugLevel() {
        // The commands, replies and events name the onion addresses of the user and of peers. A log at info level,
        // which users share in bug reports, would link the identities of a user.
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        startControlServer(command -> "250-ServiceID=" + serviceId + "\r\n250 OK\r\n");

        torControlProtocol.addOnion(onionServiceKey, 9999, 12345);

        List<ILoggingEvent> eventsWithServiceId;
        synchronized (appender) {
            eventsWithServiceId = appender.list.stream()
                    .filter(event -> event.getFormattedMessage().contains(serviceId))
                    .toList();
        }
        assertThat(eventsWithServiceId).isNotEmpty().allMatch(event -> event.getLevel() == Level.DEBUG);
    }

    @Test
    void replyWithPrivateKeyIsNotLogged() {
        OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
        String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
        // Tor sends a PrivateKey line if it generates the key (ADD_ONION NEW:...)
        String generatedSecretScalar = TestKeys.randomBase64SecretScalar();
        startControlServer(command -> "250-ServiceID=" + serviceId + "\r\n" +
                "250-PrivateKey=ED25519-V3:" + generatedSecretScalar + "\r\n" +
                "250 OK\r\n");

        torControlProtocol.addOnion(onionServiceKey, 9999, 12345);

        List<String> messages = loggedMessages();
        assertThat(messages).noneMatch(message -> message.contains(generatedSecretScalar));
        assertThat(messages).contains("Received reply from Tor control server: 250-PrivateKey=[hidden]");
    }

    @Test
    void authenticateDoesNotLogThePassword() {
        PasswordDigest passwordDigest = PasswordDigest.generateDigest();
        String password = BaseEncoding.base16().lowerCase().encode(passwordDigest.getSecret());
        startControlServer(command -> "250 OK\r\n");

        torControlProtocol.authenticate(passwordDigest);

        List<String> messages = loggedMessages();
        assertThat(messages).noneMatch(message -> message.contains(password));
        assertThat(messages).anyMatch(message -> message.startsWith("Send Tor control command: AUTHENTICATE"));
    }

    @Test
    void failedSetConfigDoesNotLogOrThrowTheValue() {
        String secretValue = "secret-proxy-password";
        startControlServer(command -> "552 Unrecognized option\r\n");

        assertThatThrownBy(() -> torControlProtocol.setConfig("Socks5ProxyPassword", secretValue))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("Socks5ProxyPassword")
                .hasMessageNotContaining(secretValue);

        List<String> messages = loggedMessages();
        assertThat(messages).noneMatch(message -> message.contains(secretValue));
        assertThat(messages).contains("Send Tor control command: SETCONF [hidden]");
    }

    @Test
    void closingTheConnectionLogsNoError() throws Exception {
        // Every shutdown closes the connection; the end of the stream which the reader sees then is expected.
        startControlServer(command -> "250 OK\r\n");
        CountDownLatch connectionEnd = new CountDownLatch(1);
        torControlProtocol.addConnectionEndListener(connectionEnd::countDown);

        torControlProtocol.close();

        assertThat(connectionEnd.await(5, TimeUnit.SECONDS)).isTrue();
        List<ILoggingEvent> warningsAndErrors;
        synchronized (appender) {
            warningsAndErrors = appender.list.stream()
                    .filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
                    .collect(Collectors.toList());
        }
        assertThat(warningsAndErrors).isEmpty();
    }

    @Test
    void theMessageOfAnInvalidReplyHidesTheValuesOfItsData() {
        // The message of the exception ends up in a log, and an unexpected reply can carry a key which Tor generated.
        String secretScalar = TestKeys.randomBase64SecretScalar();
        startControlServer(command -> "250-PrivateKey=ED25519-V3:" + secretScalar + "\r\n250 OK\r\n");

        assertThatThrownBy(() -> torControlProtocol.getInfo("version"))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("250-PrivateKey=[hidden]")
                .hasMessageNotContaining(secretScalar);
        assertThat(loggedMessages()).noneMatch(message -> message.contains(secretScalar));
    }

    @Test
    void anUnknownEventIsLoggedInItsLoggableForm() {
        String secretValue = "secret-value";
        TorControlReader reader = new TorControlReader();

        readEventAndReply(reader, "650 PrivateKey=" + secretValue);

        assertThat(loggedMessages())
                .noneMatch(message -> message.contains(secretValue))
                .contains("Unknown Tor event: 650 PrivateKey=[hidden]");
    }

    @Test
    void aMalformedEventIsLoggedWithItsTextAtDebugLevelOnly() {
        // The text of an event can name an onion address, and the parser quotes a malformed field in its exception.
        String serviceId = TestKeys.randomOnionServiceKey().getOnionAddress().replace(".onion", "");
        TorControlReader reader = new TorControlReader();
        reader.addBootstrapEventListener(new BootstrapEventListener(EventType.STATUS_CLIENT) {
            @Override
            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
            }
        });

        readEventAndReply(reader, "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=" + serviceId + " TAG=a SUMMARY=\"b\"");

        assertEventTextOnlyAtDebugLevel(serviceId, "Could not handle a Tor event");
    }

    @Test
    void anEventWhichAListenerCannotHandleIsLoggedWithItsTextAtDebugLevelOnly() {
        String serviceId = TestKeys.randomOnionServiceKey().getOnionAddress().replace(".onion", "");
        TorControlReader reader = new TorControlReader();
        reader.addHsDescEventListener(new HsDescEventListener(EventType.HS_DESC) {
            @Override
            public void onHsDescEvent(HsDescEvent hsDescEvent) {
                throw new IllegalStateException("Cannot handle the event of " + hsDescEvent.getHsAddress());
            }
        });

        readEventAndReply(reader, "650 HS_DESC RECEIVED " + serviceId + " NO_AUTH " +
                "$0123456789ABCDEF0123456789ABCDEF01234567 descriptorId");

        assertEventTextOnlyAtDebugLevel(serviceId, "A listener could not handle a Tor event");
    }

    private static void readEventAndReply(TorControlReader reader, String event) {
        reader.start(new ByteArrayInputStream((event + "\r\n250 OK\r\n").getBytes(StandardCharsets.US_ASCII)));
        // The reader handles the event before it queues the reply which follows it.
        assertThat(reader.readLine()).isEqualTo("250 OK");
        reader.close();
    }

    private void assertEventTextOnlyAtDebugLevel(String serviceId, String warning) {
        List<ILoggingEvent> events;
        synchronized (appender) {
            events = List.copyOf(appender.list);
        }
        assertThat(events)
                .filteredOn(event -> event.getLevel().isGreaterOrEqual(Level.INFO))
                .noneMatch(event -> textOf(event).contains(serviceId))
                .anyMatch(event -> event.getLevel() == Level.WARN && event.getFormattedMessage().startsWith(warning));
        assertThat(events)
                .filteredOn(event -> event.getLevel() == Level.DEBUG && event.getThrowableProxy() != null)
                .anyMatch(event -> event.getFormattedMessage().contains(serviceId));
    }

    // The message with the messages of the logged exception and its causes
    private static String textOf(ILoggingEvent event) {
        StringBuilder text = new StringBuilder(event.getFormattedMessage());
        for (IThrowableProxy throwable = event.getThrowableProxy(); throwable != null; throwable = throwable.getCause()) {
            text.append('\n').append(throwable.getMessage());
        }
        return text.toString();
    }

    private void startControlServer(Function<String, String> replyByCommand) {
        serverThread = new Thread(() -> {
            try (Socket socket = serverSocket.accept();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
                 OutputStream outputStream = socket.getOutputStream()) {
                String command;
                while ((command = reader.readLine()) != null) {
                    outputStream.write(replyByCommand.apply(command).getBytes(StandardCharsets.US_ASCII));
                    outputStream.flush();
                }
            } catch (IOException ignore) {
                // The test closes the sockets
            }
        }, "FakeTorControlServer");
        serverThread.start();
        torControlProtocol.initialize(serverSocket.getLocalPort());
    }

    private List<String> loggedMessages() {
        // The reader thread logs a reply before the protocol can take it, so all lines of the reply are logged here
        synchronized (appender) {
            return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        }
    }
}
