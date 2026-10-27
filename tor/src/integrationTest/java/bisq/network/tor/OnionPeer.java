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

import bisq.network.tor.common.platform.OS;
import bisq.network.tor.onionservice.OnionServiceKey;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.stream.Stream;

/**
 * A peer as Bisq runs one: a TorService with an onion service of its own key. Its server answers each message with an
 * acknowledgement (see {@link AckServer}).
 */
@Slf4j
final class OnionPeer implements AutoCloseable {
    static final int ONION_SERVICE_PORT = 9999;
    private static final long RETRY_DELAY_MS = 2_000;
    private static final PlatformServices PLATFORM_SERVICES = new PlatformServices() {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return ProcessHandle.allProcesses().map(process -> process.info().command().orElse(""));
        }

        @Override
        public boolean supportsPosixPermissions() {
            return !OS.isWindows();
        }
    };

    private final String name;
    @Getter
    private final TorService torService;
    private final OnionServiceKey onionServiceKey;
    // How long the peer tries to reach a server, see send
    private final Duration connectTimeout;
    private AckServer ackServer;

    private OnionPeer(String name, TorTransportConfig transportConfig, Duration connectTimeout) {
        this.name = name;
        torService = new TorService(transportConfig, PLATFORM_SERVICES);
        onionServiceKey = OnionServiceKeys.generate();
        this.connectTimeout = connectTimeout;
    }

    /**
     * Starts the Tor of the peer and publishes its onion service.
     */
    static OnionPeer start(String name, TorTransportConfig transportConfig, Duration connectTimeout)
            throws InterruptedException {
        OnionPeer peer = new OnionPeer(name, transportConfig, connectTimeout);
        try {
            peer.startTorAndPublish();
        } catch (RuntimeException e) {
            peer.close();
            throw e;
        }
        return peer;
    }

    String getOnionAddress() {
        return onionServiceKey.getOnionAddress();
    }

    /**
     * Stops Tor and starts it again with the onion service of the same key, as Bisq does after a restart.
     */
    void restart() throws InterruptedException {
        ackServer.close();
        torService.shutdown().join();
        startTorAndPublish();
    }

    /**
     * Sends the message to the server through Tor and returns its answer. A new onion service is reachable only once
     * its descriptor has reached the directories, and the circuits of a connection can fail, so the peer tries again
     * until the connect timeout has passed.
     */
    String send(String host, int port, String message) throws InterruptedException {
        long deadline = System.nanoTime() + connectTimeout.toNanos();
        IOException lastFailure;
        int attempt = 0;
        do {
            attempt++;
            try (Socket socket = torService.getSocket(host, port, name + "-to-" + host, AckServer.SOCKET_TIMEOUT_MS)) {
                return AckServer.exchange(socket, message);
            } catch (IOException e) {
                lastFailure = e;
                log.info("{}: attempt {} to reach {}:{} failed: {}", name, attempt, host, port, e.toString());
                Thread.sleep(RETRY_DELAY_MS);
            }
        } while (System.nanoTime() < deadline);
        throw new AssertionError(name + " could not reach " + host + ":" + port + " within " + connectTimeout +
                " in " + attempt + " attempts", lastFailure);
    }

    String send(OnionPeer receiver, String message) throws InterruptedException {
        return send(receiver.getOnionAddress(), ONION_SERVICE_PORT, message);
    }

    private void startTorAndPublish() {
        torService.initialize().join();
        ServerSocket serverSocket = torService.publishOnionServiceAndCreateServerSocket(ONION_SERVICE_PORT,
                onionServiceKey).join();
        ackServer = AckServer.start(name, serverSocket);
        log.info("{} published its onion service {}", name, getOnionAddress());
    }

    @Override
    public void close() throws InterruptedException {
        if (ackServer != null) {
            ackServer.close();
        }
        torService.shutdown().join();
    }
}
