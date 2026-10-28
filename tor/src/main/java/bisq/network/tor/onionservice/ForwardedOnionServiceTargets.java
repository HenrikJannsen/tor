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
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Tor reaches the onion services of Bisq only through ports which sandy forwards out of the sandbox. sandy fixes the
 * forwarded ports when Tor starts, but Bisq creates onion services later. Therefore Bisq reserves a pool of port pairs
 * before Tor starts: Tor connects to the inner port, sandy relays to the outer port, and Bisq listens there.
 * <p>
 * Bisq binds the outer ports when it creates the pool and keeps them bound, so no other process can take them. An onion
 * service keeps its pair until Tor ends. When the pool is exhausted, creating another onion service fails.
 * <p>
 * The messages of the exceptions name no onion address: they can end up in a log which the user shares, where the
 * addresses would link the identities of the user. The caller knows the address.
 */
@Slf4j
public final class ForwardedOnionServiceTargets implements OnionServiceTargets {
    private static final int BACKLOG = 50;

    public record PortPair(int innerPort, int outerPort) {
    }

    private static final class Slot {
        private final PortPair portPair;
        private ServerSocket serverSocket;
        private boolean isServerSocketHandedOut;
        private Optional<LoopbackRelay> relay = Optional.empty();

        private Slot(PortPair portPair, ServerSocket serverSocket) {
            this.portPair = portPair;
            this.serverSocket = serverSocket;
        }
    }

    private final List<Slot> allSlots;
    private final Deque<Slot> freeSlots;
    private final Map<String, Slot> slotByOnionAddress = new HashMap<>();
    private final String poolSizeConfigKey;

    /**
     * @param serverSockets      bound loopback server sockets; their ports are the outer ports
     * @param innerPorts         free loopback ports for the relay inside the sandbox, one per server socket
     * @param poolSizeConfigKey  named in the error when the pool is exhausted
     */
    public ForwardedOnionServiceTargets(List<ServerSocket> serverSockets,
                                        List<Integer> innerPorts,
                                        String poolSizeConfigKey) {
        checkArgument(serverSockets.size() == innerPorts.size(), "Need one inner port per server socket");
        List<Slot> slots = new ArrayList<>();
        for (int i = 0; i < serverSockets.size(); i++) {
            ServerSocket serverSocket = serverSockets.get(i);
            slots.add(new Slot(new PortPair(innerPorts.get(i), serverSocket.getLocalPort()), serverSocket));
        }
        allSlots = List.copyOf(slots);
        freeSlots = new ArrayDeque<>(slots);
        this.poolSizeConfigKey = poolSizeConfigKey;
    }

    /**
     * The pool and the ports of the listeners of Tor. Both are allocated together, while the outer server sockets of
     * the pool are bound, so that all ports differ.
     */
    public record Reservation(ForwardedOnionServiceTargets targets, List<Integer> listenerPorts) {
    }

    @VisibleForTesting
    interface PortAllocator {
        List<Integer> allocate(int count) throws IOException;
    }

    /**
     * Binds the outer server sockets of a pool of {@code poolSize} port pairs, and allocates their inner ports together
     * with {@code numListenerPorts} ports for the listeners of Tor.
     */
    public static Reservation reserve(int poolSize, int numListenerPorts, String poolSizeConfigKey) throws IOException {
        return reserve(bindOuterServerSockets(poolSize), numListenerPorts, poolSizeConfigKey, LoopbackPorts::allocate);
    }

    /**
     * @param serverSockets the bound outer server sockets. If the allocation fails, they are closed, because no pool
     *                      refers to them then.
     */
    @VisibleForTesting
    static Reservation reserve(List<ServerSocket> serverSockets,
                               int numListenerPorts,
                               String poolSizeConfigKey,
                               PortAllocator portAllocator) throws IOException {
        List<Integer> ports;
        try {
            ports = portAllocator.allocate(numListenerPorts + serverSockets.size());
        } catch (IOException | RuntimeException e) {
            closeAll(serverSockets);
            throw e;
        }
        ForwardedOnionServiceTargets targets = new ForwardedOnionServiceTargets(serverSockets,
                ports.subList(numListenerPorts, ports.size()),
                poolSizeConfigKey);
        return new Reservation(targets, ports.subList(0, numListenerPorts));
    }

    /**
     * Binds {@code count} loopback server sockets for the outer ports.
     */
    @VisibleForTesting
    static List<ServerSocket> bindOuterServerSockets(int count) throws IOException {
        List<ServerSocket> serverSockets = new ArrayList<>(count);
        try {
            for (int i = 0; i < count; i++) {
                serverSockets.add(new ServerSocket(0, BACKLOG, LoopbackPorts.IPV4_LOOPBACK));
            }
            return serverSockets;
        } catch (IOException e) {
            closeAll(serverSockets);
            throw e;
        }
    }

    private static void closeAll(List<ServerSocket> serverSockets) {
        for (ServerSocket serverSocket : serverSockets) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                log.debug("Could not close server socket on port {}", serverSocket.getLocalPort(), e);
            }
        }
    }

    public List<PortPair> getPortPairs() {
        return allSlots.stream().map(slot -> slot.portPair).collect(Collectors.toList());
    }

    @Override
    public synchronized Target bindServerSocket(String onionAddress) throws IOException {
        Slot slot = getOrAssignSlot(onionAddress);
        if (slot.relay.isPresent()) {
            throw new IOException("The onion service already relays to a local server");
        }
        if (slot.isServerSocketHandedOut) {
            if (!slot.serverSocket.isClosed()) {
                throw new IOException("The server socket of the onion service is still open");
            }
            slot.serverSocket = new ServerSocket(slot.portPair.outerPort(), BACKLOG, LoopbackPorts.IPV4_LOOPBACK);
        }
        slot.isServerSocketHandedOut = true;
        return new Target(slot.serverSocket, slot.portPair.innerPort());
    }

    @Override
    public synchronized int targetPortOf(String onionAddress, int localPort) throws IOException {
        Slot slot = getOrAssignSlot(onionAddress);
        if (slot.isServerSocketHandedOut) {
            throw new IOException("The onion service already has its own server socket");
        }
        if (slot.relay.isPresent()) {
            // A retry with another server of the application. A new relay would have to bind the outer port again,
            // which the old relay frees only once its accept has returned, and another process could take it before.
            slot.relay.get().setTargetPort(localPort);
            return slot.portPair.innerPort();
        }
        LoopbackRelay relay = new LoopbackRelay(slot.serverSocket, localPort);
        slot.relay = Optional.of(relay);
        relay.start();
        return slot.portPair.innerPort();
    }

    // The relays connect to the server of the application on the loopback address.
    @Override
    public InetAddress getBindAddress() {
        return LoopbackPorts.IPV4_LOOPBACK;
    }

    /**
     * Closes the relays and the server sockets which no onion service uses. The server sockets of onion services
     * belong to their nodes, which close them.
     */
    @Override
    public synchronized void close() {
        for (Slot slot : allSlots) {
            slot.relay.ifPresent(LoopbackRelay::close);
            if (!slot.isServerSocketHandedOut) {
                try {
                    slot.serverSocket.close();
                } catch (IOException e) {
                    log.debug("Could not close server socket on port {}", slot.portPair.outerPort(), e);
                }
            }
        }
    }

    private Slot getOrAssignSlot(String onionAddress) throws IOException {
        Slot slot = slotByOnionAddress.get(onionAddress);
        if (slot != null) {
            return slot;
        }
        slot = freeSlots.poll();
        if (slot == null) {
            throw new IOException("All " + allSlots.size() + " ports which the Tor sandbox forwards for onion " +
                    "services are in use, so another onion service cannot be created. " +
                    "Increase " + poolSizeConfigKey + " and restart Bisq.");
        }
        slotByOnionAddress.put(onionAddress, slot);
        return slot;
    }
}
