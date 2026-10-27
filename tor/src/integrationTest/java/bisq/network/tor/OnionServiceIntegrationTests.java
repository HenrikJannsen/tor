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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The use cases of the peer message test of netlayer, on the Tor network of a subclass: two peers publish onion
 * services of their own keys and send each other messages through Tor. A subclass with a network to start overrides
 * {@link #startNetwork()} and {@link #stopNetwork()}.
 */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class OnionServiceIntegrationTests {
    private static final long ONLINE_CHECK_RETRY_DELAY_MS = 2_000;
    // How long a test waits after the start of the upload of a descriptor until the directories store it. On the
    // private network it took 0.2 s; on the public Tor network the upload goes through circuits and takes longer.
    private static final Duration DESCRIPTOR_UPLOAD_TIME = Duration.ofSeconds(10);

    // A field with @TempDir would be set only before each test, after startNetworkAndPeers
    Path tempDir;
    OnionPeer alice;
    OnionPeer bob;

    abstract TorTransportConfig createTransportConfig(Path torDir);

    // How long a peer tries to reach a server through Tor. It depends on the network.
    abstract Duration getConnectTimeout();

    void startNetwork() throws Exception {
    }

    void stopNetwork() throws Exception {
    }

    OnionPeer startPeer(String name) throws InterruptedException {
        return OnionPeer.start(name, createTransportConfig(tempDir.resolve(name)), getConnectTimeout());
    }

    // The timeout of a test class does not cover this method
    @BeforeAll
    @Timeout(value = 15, unit = TimeUnit.MINUTES)
    void startNetworkAndPeers(@TempDir Path tempDir) throws Exception {
        this.tempDir = tempDir;
        startNetwork();
        alice = startPeer("alice");
        bob = startPeer("bob");
    }

    @AfterAll
    void stopPeersAndNetwork() throws Exception {
        try {
            for (OnionPeer peer : new OnionPeer[]{bob, alice}) {
                if (peer != null) {
                    peer.close();
                }
            }
        } finally {
            stopNetwork();
        }
    }

    @Test
    void aliceReachesTheOnionServiceOfBob() throws InterruptedException {
        String message = "hello bob, this is alice";

        assertThat(alice.send(bob, message)).isEqualTo(AckServer.ackOf("bob", message));
    }

    @Test
    void bobReachesTheOnionServiceOfAlice() throws InterruptedException {
        String message = "hello alice, this is bob";

        assertThat(bob.send(alice, message)).isEqualTo(AckServer.ackOf("alice", message));
    }

    @Test
    void thePublishedOnionServiceOfBobIsOnline() throws InterruptedException {
        assertThat(isOnlineWithinTheConnectTimeout(alice, bob.getOnionAddress())).isTrue();
    }

    // Bisq publishes the onion service of the same key at each start, so its peers keep its address
    @Test
    void aPeerKeepsItsOnionAddressWhenItsTorRestarts() throws InterruptedException {
        try (OnionPeer carol = startPeer("carol")) {
            assertThat(alice.send(carol, "before the restart")).isEqualTo(AckServer.ackOf("carol", "before the restart"));

            carol.restart();
            // TorService completes a publication when Tor starts to upload the descriptor. Until the upload is done,
            // the directories hand out the descriptor of the first Tor of carol, one of whose introduction points can
            // still accept an introduction, and the client then waits for minutes for a rendezvous which never comes.
            Thread.sleep(DESCRIPTOR_UPLOAD_TIME.toMillis());

            // Bob has no descriptor of carol yet. Alice still has the descriptor of the first Tor; on the public Tor
            // network her Tor did not reach carol within minutes after the restart.
            assertThat(bob.send(carol, "after the restart")).isEqualTo(AckServer.ackOf("carol", "after the restart"));
        }
    }

    // Right after a publication, the descriptor may not have reached the directories which a lookup asks
    boolean isOnlineWithinTheConnectTimeout(OnionPeer peer, String onionAddress) throws InterruptedException {
        long deadline = System.nanoTime() + getConnectTimeout().toNanos();
        do {
            try {
                if (peer.getTorService().isOnionServiceOnlineAsync(onionAddress).join()) {
                    return true;
                }
            } catch (CompletionException e) {
                log.info("The lookup of an onion service failed: {}", e.getCause().toString());
            }
            Thread.sleep(ONLINE_CHECK_RETRY_DELAY_MS);
        } while (System.nanoTime() < deadline);
        return false;
    }
}
