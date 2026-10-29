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
import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Copies the bytes of every connection accepted on {@code listener} to a new connection to a loopback port and back.
 * Used for an onion service whose server Bisq does not create itself (the API server), when Tor reaches Bisq only
 * through a forwarded port.
 */
@Slf4j
final class LoopbackRelay implements AutoCloseable {
    static final int MAX_CONNECTIONS = 64;
    // A connection without a byte in either direction for this time ends, so that idle connections cannot take the
    // slots of the relay for good, for example of a client which keeps its side open after the server closed its
    // side. The server of the Bisq 2 API closes an idle WebSocket after 15 minutes (the default of Grizzly) and an
    // idle HTTP connection sooner, so the relay ends no connection which the server keeps.
    static final long IDLE_TIMEOUT_MS = TimeUnit.MINUTES.toMillis(15);
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int BUFFER_SIZE = 16 * 1024;
    private static final long REFUSAL_REPORT_INTERVAL_MS = TimeUnit.MINUTES.toMillis(1);

    private final ServerSocket listener;
    // The port of the server of the application. A retry of the publication can move the relay to another server.
    private volatile int targetPort;
    private final int idleTimeoutMs;
    private final ExecutorService executor;
    // The sockets of every connection from its accept until its end, which close() closes. A connection is registered
    // and the relay closed under this lock, so that close() finds every connection which the relay accepted before it,
    // and a connection which the relay accepted during its close is not relayed.
    private final Object registrationLock = new Object();
    private final Set<Socket> openSockets = ConcurrentHashMap.newKeySet();
    private final AtomicInteger numConnections = new AtomicInteger();
    // Used only by the thread which accepts the connections
    private final RefusalReport refusalReport = new RefusalReport(REFUSAL_REPORT_INTERVAL_MS);
    private volatile boolean isClosed;

    LoopbackRelay(ServerSocket listener, int targetPort) {
        this(listener, targetPort, IDLE_TIMEOUT_MS);
    }

    @VisibleForTesting
    LoopbackRelay(ServerSocket listener, int targetPort, long idleTimeoutMs) {
        this.listener = listener;
        this.targetPort = targetPort;
        this.idleTimeoutMs = Math.toIntExact(idleTimeoutMs);
        // One thread accepts, two copy the bytes of each connection.
        executor = new ThreadPoolExecutor(1, 2 * MAX_CONNECTIONS + 1, 30, TimeUnit.SECONDS, new SynchronousQueue<>(),
                new ThreadFactoryBuilder().setNameFormat("LoopbackRelay-" + listener.getLocalPort() + "-%d").setDaemon(true).build());
    }

    void start() {
        executor.submit(this::acceptConnections);
    }

    /**
     * Relays the connections which arrive from now on to another server of the application. The listener stays bound,
     * so that no other process can take its port, and the connections which run already stay with the old server.
     */
    void setTargetPort(int targetPort) {
        this.targetPort = targetPort;
    }

    @Override
    public void close() {
        List<Socket> socketsOfTheConnections;
        synchronized (registrationLock) {
            isClosed = true;
            socketsOfTheConnections = new ArrayList<>(openSockets);
        }
        closeQuietly(listener);
        socketsOfTheConnections.forEach(LoopbackRelay::closeQuietly);
        executor.shutdownNow();
    }

    private void acceptConnections() {
        while (!isClosed) {
            Socket inbound;
            try {
                inbound = listener.accept();
            } catch (IOException e) {
                if (!isClosed) {
                    log.warn("Relay to port {} stopped accepting connections", targetPort, e);
                }
                return;
            }
            if (numConnections.incrementAndGet() > MAX_CONNECTIONS) {
                numConnections.decrementAndGet();
                int refusals = refusalReport.onRefusal(System.nanoTime());
                if (refusals > 0) {
                    log.warn("Relay to port {} has {} connections. Number of new connections which it closed since " +
                                    "its last report: {}. It reports at most once a minute.", targetPort, MAX_CONNECTIONS,
                            refusals);
                }
                closeQuietly(inbound);
                continue;
            }
            Socket outbound = new Socket();
            if (!register(inbound, outbound)) {
                // The relay was closed after it accepted the connection.
                numConnections.decrementAndGet();
                closeQuietly(inbound);
                closeQuietly(outbound);
                return;
            }
            try {
                executor.submit(() -> relay(inbound, outbound));
            } catch (RejectedExecutionException e) {
                closeConnection(inbound, outbound);
            }
        }
    }

    // Before the connection goes to a worker, so that close() never misses a connection which it has to end
    private boolean register(Socket inbound, Socket outbound) {
        synchronized (registrationLock) {
            if (isClosed) {
                return false;
            }
            openSockets.add(inbound);
            openSockets.add(outbound);
            return true;
        }
    }

    /**
     * Which refused connections the relay reports: the first, and then at most one per interval, with the number of the
     * connections which it closed since its last report. A client which opens connections without end can then not
     * fill the log.
     */
    @VisibleForTesting
    static final class RefusalReport {
        private final long intervalNanos;
        private boolean hasReported;
        private long lastReportNanos;
        private int refusalsSinceReport;

        RefusalReport(long intervalMs) {
            this.intervalNanos = TimeUnit.MILLISECONDS.toNanos(intervalMs);
        }

        /**
         * @param nowNanos the time of the refusal, from {@link System#nanoTime()}
         * @return the number of refused connections to report now, this one included, or 0 if no report is due
         */
        int onRefusal(long nowNanos) {
            refusalsSinceReport++;
            if (hasReported && nowNanos - lastReportNanos < intervalNanos) {
                return 0;
            }
            hasReported = true;
            lastReportNanos = nowNanos;
            int refusals = refusalsSinceReport;
            refusalsSinceReport = 0;
            return refusals;
        }
    }

    private void relay(Socket inbound, Socket outbound) {
        int targetPort = this.targetPort;
        AtomicInteger openDirections = new AtomicInteger(2);
        Runnable onDirectionDone = () -> {
            if (openDirections.decrementAndGet() == 0) {
                closeConnection(inbound, outbound);
            }
        };
        // The last time at which a byte went through in either direction
        AtomicLong lastTransfer = new AtomicLong(System.nanoTime());
        try {
            // A read waits at most the idle timeout. Then the direction checks whether the connection is idle.
            inbound.setSoTimeout(idleTimeoutMs);
            outbound.setSoTimeout(idleTimeoutMs);
            outbound.connect(new InetSocketAddress(LoopbackPorts.IPV4_LOOPBACK, targetPort), CONNECT_TIMEOUT_MS);
            executor.submit(() -> copy(outbound, inbound, lastTransfer, onDirectionDone));
            copy(inbound, outbound, lastTransfer, onDirectionDone);
        } catch (IOException | RejectedExecutionException e) {
            log.debug("Relay to port {} failed", targetPort, e);
            closeConnection(inbound, outbound);
        }
    }

    private void copy(Socket from, Socket to, AtomicLong lastTransfer, Runnable onDone) {
        byte[] buffer = new byte[BUFFER_SIZE];
        try {
            InputStream inputStream = from.getInputStream();
            OutputStream outputStream = to.getOutputStream();
            int read;
            while ((read = readUnlessIdle(inputStream, buffer, lastTransfer)) != -1) {
                lastTransfer.set(System.nanoTime());
                outputStream.write(buffer, 0, read);
                outputStream.flush();
                lastTransfer.set(System.nanoTime());
            }
            // Pass the end of the stream on, so that a peer which closes its sending side still gets the reply.
            to.shutdownOutput();
        } catch (IOException e) {
            // Also the end of an idle connection. Closing both sockets ends the other direction as well.
            closeQuietly(from);
            closeQuietly(to);
        } finally {
            onDone.run();
        }
    }

    /**
     * @throws SocketTimeoutException if no byte went through in either direction for the idle timeout. A direction
     *                                which waits for its peer while the other direction carries data goes on waiting.
     */
    private int readUnlessIdle(InputStream inputStream, byte[] buffer, AtomicLong lastTransfer) throws IOException {
        while (true) {
            try {
                return inputStream.read(buffer);
            } catch (SocketTimeoutException e) {
                if (System.nanoTime() - lastTransfer.get() >= TimeUnit.MILLISECONDS.toNanos(idleTimeoutMs)) {
                    throw e;
                }
            }
        }
    }

    private void closeConnection(Socket inbound, Socket outbound) {
        if (openSockets.remove(inbound)) {
            numConnections.decrementAndGet();
        }
        openSockets.remove(outbound);
        closeQuietly(inbound);
        closeQuietly(outbound);
    }

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignore) {
        }
    }
}
