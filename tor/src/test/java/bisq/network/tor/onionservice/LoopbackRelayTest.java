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

package bisq.network.tor.onionservice;

import bisq.network.tor.process.LoopbackPorts;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The relay carries the connections of an onion service, in Bisq 2 of the API, from Tor in its sandbox to the server of
 * the application. Anybody who knows the onion address can open connections to it.
 */
@Timeout(30)
class LoopbackRelayTest {
    private static final int READ_TIMEOUT_MS = 5000;

    private final List<Socket> sockets = new CopyOnWriteArrayList<>();
    private ServerSocket applicationServer;
    private ServerSocket relayListener;
    private LoopbackRelay relay;

    @AfterEach
    void tearDown() throws IOException {
        if (relay != null) {
            relay.close();
        }
        for (Socket socket : sockets) {
            socket.close();
        }
        if (applicationServer != null) {
            applicationServer.close();
        }
    }

    @Test
    void anIdleConnectionEndsAfterTheIdleTimeout() throws Exception {
        startApplicationServer(LoopbackRelayTest::echo);
        startRelay(300);

        Socket client = connectToRelay();

        // The relay closes the connection, so the client reads the end of the stream instead of waiting.
        assertThat(client.getInputStream().read()).isEqualTo(-1);
    }

    @Test
    void aConnectionWithTrafficInOneDirectionIsNotIdle() throws Exception {
        // The server sends a byte every 100 ms for longer than the idle timeout, while the client sends nothing, as
        // a client which waits for the updates of a WebSocket.
        int numBytes = 15;
        startApplicationServer(socket -> {
            OutputStream outputStream = socket.getOutputStream();
            for (int i = 0; i < numBytes; i++) {
                outputStream.write(i);
                outputStream.flush();
                Thread.sleep(100);
            }
            socket.close();
        });
        startRelay(300);

        Socket client = connectToRelay();

        assertThat(client.getInputStream().readAllBytes()).hasSize(numBytes);
    }

    @Test
    void idleConnectionsDoNotBlockTheRelayForGood() throws Exception {
        startApplicationServer(LoopbackRelayTest::echo);
        startRelay(500);
        for (int i = 0; i < LoopbackRelay.MAX_CONNECTIONS; i++) {
            connectToRelay();
        }
        // The relay is full: it closes the next connection at once.
        assertThat(connectToRelay().getInputStream().read()).isEqualTo(-1);

        // Once the idle connections have ended, a new connection gets through.
        while (!echoesThroughTheRelay()) {
            Thread.sleep(100);
        }
    }

    @Test
    void theRelayClosesConnectionsAboveItsLimitAndKeepsTheOthers() throws Exception {
        startApplicationServer(LoopbackRelayTest::echo);
        startRelay(LoopbackRelay.IDLE_TIMEOUT_MS);
        List<Socket> clients = new ArrayList<>();
        for (int i = 0; i < LoopbackRelay.MAX_CONNECTIONS; i++) {
            clients.add(connectToRelay());
        }

        assertThat(connectToRelay().getInputStream().read()).isEqualTo(-1);
        for (Socket client : clients) {
            assertThat(echoes(client)).isTrue();
        }

        // A connection which ends frees its slot.
        clients.get(0).close();
        while (!echoesThroughTheRelay()) {
            Thread.sleep(100);
        }
    }

    // Anybody who knows the onion address can open connections without end.
    @Test
    void connectionsAboveTheLimitDoNotFillTheLog() throws Exception {
        Logger relayLogger = (Logger) LoggerFactory.getLogger(LoopbackRelay.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        relayLogger.addAppender(appender);
        try {
            startApplicationServer(LoopbackRelayTest::echo);
            startRelay(LoopbackRelay.IDLE_TIMEOUT_MS);
            for (int i = 0; i < LoopbackRelay.MAX_CONNECTIONS; i++) {
                connectToRelay();
            }

            for (int i = 0; i < 20; i++) {
                assertThat(connectToRelay().getInputStream().read()).isEqualTo(-1);
            }

            assertThat(appender.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .singleElement()
                    .satisfies(event -> assertThat(event.getFormattedMessage())
                            .contains("has " + LoopbackRelay.MAX_CONNECTIONS + " connections")
                            .contains("since its last report: 1."));
        } finally {
            relayLogger.detachAppender(appender);
        }
    }

    @Test
    void theRelayReportsTheFirstRefusalAndThenAtMostOncePerIntervalWithTheCount() {
        var report = new LoopbackRelay.RefusalReport(60_000);
        // System.nanoTime() can be negative.
        long start = -TimeUnit.MINUTES.toNanos(5);

        assertThat(report.onRefusal(start)).isEqualTo(1);
        assertThat(report.onRefusal(start + TimeUnit.SECONDS.toNanos(1))).isZero();
        assertThat(report.onRefusal(start + TimeUnit.SECONDS.toNanos(59))).isZero();
        assertThat(report.onRefusal(start + TimeUnit.SECONDS.toNanos(60))).isEqualTo(3);
        assertThat(report.onRefusal(start + TimeUnit.SECONDS.toNanos(61))).isZero();
        // After a quiet time the next refusal reports the one which nobody reported yet.
        assertThat(report.onRefusal(start + TimeUnit.MINUTES.toNanos(30))).isEqualTo(2);
    }

    // The close finds the connection which the relay registers meanwhile: it waits for the registration.
    @Test
    void aCloseDuringTheRegistrationOfAConnectionEndsTheConnection() throws Exception {
        startApplicationServer(LoopbackRelayTest::echo);
        HoldingListener listener = startRelayWith(new HoldingListener(HoldPoint.REGISTRATION));
        Socket client = connectToRelay();
        HeldSocket inbound = listener.awaitHeldSocket();

        CompletableFuture<Void> closing = CompletableFuture.runAsync(relay::close);
        try {
            assertThatThrownBy(() -> closing.get(300, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
        } finally {
            inbound.release();
        }
        closing.get(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);

        assertThat(inbound.isClosed()).isTrue();
        assertThat(client.getInputStream().read()).isEqualTo(-1);
    }

    // The close took the list of the connections which it ends before it closes the listener, which accepts meanwhile.
    @Test
    void aConnectionWhichTheRelayAcceptsDuringItsCloseIsNotRelayed() throws Exception {
        applicationServer = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK);
        HoldingListener listener = startRelayWith(new HoldingListener(HoldPoint.LISTENER_CLOSE));
        // A relay which is closed before it accepts does not accept.
        assertThat(listener.isAccepting.await(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)).isTrue();

        CompletableFuture<Void> closing = CompletableFuture.runAsync(relay::close);
        try {
            assertThat(listener.isCloseHeld.await(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)).isTrue();
            assertThat(connectToRelay().getInputStream().read()).isEqualTo(-1);
        } finally {
            listener.isCloseReleased.countDown();
        }
        closing.get(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);

        // The relay does not connect to the server for that connection.
        applicationServer.setSoTimeout(1000);
        assertThatThrownBy(applicationServer::accept).isInstanceOf(SocketTimeoutException.class);
    }

    // A worker holds a registered connection before it connects to the server and starts the copies.
    @Test
    void aCloseWhileAWorkerHoldsARegisteredConnectionEndsTheConnection() throws Exception {
        applicationServer = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK);
        HoldingListener listener = startRelayWith(new HoldingListener(HoldPoint.WORKER));
        Socket client = connectToRelay();
        HeldSocket inbound = listener.awaitHeldSocket();

        try {
            relay.close();
        } finally {
            inbound.release();
        }

        assertThat(inbound.isClosed()).isTrue();
        assertThat(client.getInputStream().read()).isEqualTo(-1);
        // The worker does not connect to the server after the close.
        applicationServer.setSoTimeout(1000);
        assertThatThrownBy(applicationServer::accept).isInstanceOf(SocketTimeoutException.class);
    }

    @Test
    void aClientWhichClosesItsSendingSideStillGetsTheReply() throws Exception {
        // The server answers once it has read the whole request, as a server which reads to the end of the stream.
        startApplicationServer(socket -> {
            byte[] request = socket.getInputStream().readAllBytes();
            socket.getOutputStream().write(("reply to " + new String(request, StandardCharsets.US_ASCII))
                    .getBytes(StandardCharsets.US_ASCII));
            socket.close();
        });
        startRelay(LoopbackRelay.IDLE_TIMEOUT_MS);
        Socket client = connectToRelay();

        client.getOutputStream().write("request".getBytes(StandardCharsets.US_ASCII));
        client.shutdownOutput();

        assertThat(new String(client.getInputStream().readAllBytes(), StandardCharsets.US_ASCII))
                .isEqualTo("reply to request");
    }

    @Test
    void closingTheRelayEndsAConnectionDuringATransfer() throws Exception {
        // The server sends without end. The close of the relay, when Tor stops, must end the connection at once.
        startApplicationServer(socket -> {
            OutputStream outputStream = socket.getOutputStream();
            byte[] chunk = new byte[1024];
            while (true) {
                outputStream.write(chunk);
                outputStream.flush();
            }
        });
        startRelay(LoopbackRelay.IDLE_TIMEOUT_MS);
        Socket client = connectToRelay();
        InputStream inputStream = client.getInputStream();
        assertThat(inputStream.read(new byte[1024])).isPositive();

        relay.close();

        // The client reads what is on its way and then the end of the connection, within the read timeout.
        try {
            while (inputStream.read(new byte[16 * 1024]) != -1) {
                // Drain
            }
        } catch (SocketException e) {
            // The close reset the connection
        }
    }

    private static boolean echoes(Socket client) throws IOException {
        client.getOutputStream().write('x');
        client.getOutputStream().flush();
        return client.getInputStream().read() == 'x';
    }

    private boolean echoesThroughTheRelay() throws IOException {
        Socket client = connectToRelay();
        try {
            return echoes(client);
        } catch (SocketException e) {
            // The relay closed the connection while it was full.
            return false;
        }
    }

    private interface ConnectionHandler {
        void handle(Socket socket) throws Exception;
    }

    private static void echo(Socket socket) throws IOException {
        InputStream inputStream = socket.getInputStream();
        OutputStream outputStream = socket.getOutputStream();
        int read;
        while ((read = inputStream.read()) != -1) {
            outputStream.write(read);
            outputStream.flush();
        }
        socket.close();
    }

    private void startApplicationServer(ConnectionHandler handler) throws IOException {
        applicationServer = new ServerSocket(0, 200, LoopbackPorts.IPV4_LOOPBACK);
        Thread acceptThread = new Thread(() -> {
            while (!applicationServer.isClosed()) {
                try {
                    Socket socket = applicationServer.accept();
                    sockets.add(socket);
                    Thread handlerThread = new Thread(() -> {
                        try {
                            handler.handle(socket);
                        } catch (Exception ignore) {
                            // The relay or the test closed the socket
                        }
                    });
                    handlerThread.setDaemon(true);
                    handlerThread.start();
                } catch (IOException ignore) {
                    // The test closed the server
                }
            }
        });
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    private void startRelay(long idleTimeoutMs) throws IOException {
        relayListener = new ServerSocket(0, 200, LoopbackPorts.IPV4_LOOPBACK);
        relay = new LoopbackRelay(relayListener, applicationServer.getLocalPort(), idleTimeoutMs);
        relay.start();
    }

    private HoldingListener startRelayWith(HoldingListener listener) {
        relayListener = listener;
        relay = new LoopbackRelay(listener, applicationServer.getLocalPort(), LoopbackRelay.IDLE_TIMEOUT_MS);
        relay.start();
        return listener;
    }

    private enum HoldPoint {
        // When the relay registers the connection: the registration puts the socket into a hash set.
        REGISTRATION,
        // The first call of the worker which relays the connection
        WORKER,
        // The close of the listener by the close of the relay. The listener still accepts until it is released.
        LISTENER_CLOSE
    }

    // Accepts the connections as HeldSocket
    private static final class HoldingListener extends ServerSocket {
        private final HoldPoint holdPoint;
        private final CompletableFuture<HeldSocket> firstSocket = new CompletableFuture<>();
        private final CountDownLatch isAccepting = new CountDownLatch(1);
        private final CountDownLatch isCloseHeld = new CountDownLatch(1);
        private final CountDownLatch isCloseReleased = new CountDownLatch(1);

        HoldingListener(HoldPoint holdPoint) throws IOException {
            super(0, 200, LoopbackPorts.IPV4_LOOPBACK);
            this.holdPoint = holdPoint;
        }

        @Override
        public Socket accept() throws IOException {
            isAccepting.countDown();
            HeldSocket socket = new HeldSocket(holdPoint);
            implAccept(socket);
            socket.isArmed = true;
            firstSocket.complete(socket);
            return socket;
        }

        @Override
        public void close() throws IOException {
            if (holdPoint == HoldPoint.LISTENER_CLOSE && isCloseHeld.getCount() > 0) {
                isCloseHeld.countDown();
                awaitRelease(isCloseReleased);
            }
            super.close();
        }

        HeldSocket awaitHeldSocket() throws Exception {
            HeldSocket socket = firstSocket.get(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            assertThat(socket.isHeld.await(READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)).isTrue();
            return socket;
        }
    }

    // Holds the thread of the relay which first uses it at its hold point, until the test releases it
    private static final class HeldSocket extends Socket {
        private final HoldPoint holdPoint;
        private final CountDownLatch isHeld = new CountDownLatch(1);
        private final CountDownLatch isReleased = new CountDownLatch(1);
        private volatile boolean isArmed;

        HeldSocket(HoldPoint holdPoint) {
            this.holdPoint = holdPoint;
        }

        @Override
        public int hashCode() {
            holdAt(HoldPoint.REGISTRATION);
            return super.hashCode();
        }

        @Override
        public void setSoTimeout(int timeout) throws SocketException {
            holdAt(HoldPoint.WORKER);
            super.setSoTimeout(timeout);
        }

        void release() {
            isReleased.countDown();
        }

        private void holdAt(HoldPoint point) {
            if (point != holdPoint || !isArmed || isHeld.getCount() == 0) {
                return;
            }
            isHeld.countDown();
            awaitRelease(isReleased);
        }
    }

    // The close of the relay interrupts its threads; the held thread goes on only when the test releases it.
    private static void awaitRelease(CountDownLatch isReleased) {
        boolean isInterrupted = false;
        while (true) {
            try {
                if (isReleased.await(READ_TIMEOUT_MS * 4L, TimeUnit.MILLISECONDS)) {
                    break;
                }
                throw new IllegalStateException("The test did not release the held thread");
            } catch (InterruptedException e) {
                isInterrupted = true;
            }
        }
        if (isInterrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private Socket connectToRelay() throws IOException {
        Socket socket = new Socket(LoopbackPorts.IPV4_LOOPBACK, relayListener.getLocalPort());
        socket.setSoTimeout(READ_TIMEOUT_MS);
        sockets.add(socket);
        return socket;
    }
}
