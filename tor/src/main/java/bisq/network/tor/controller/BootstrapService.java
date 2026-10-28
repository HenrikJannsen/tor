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

import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import bisq.network.tor.controller.events.events.EventType;
import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.process.EmbeddedTorProcess;
import com.google.common.util.concurrent.MoreExecutors;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static bisq.network.tor.common.torrc.Torrc.Keys.DISABLE_NETWORK;

@Slf4j
public class BootstrapService extends BootstrapEventListener {
    private final TorControlProtocol torControlProtocol;
    private final CountDownLatch countDownLatch = new CountDownLatch(1);
    private final long timeout;
    private final Runnable connectionEndListener = this::onConnectionEnd;
    private volatile boolean isShutdown;
    private volatile boolean hasConnectionEnded;
    @Getter
    private Optional<CompletableFuture<Void>> future = Optional.empty();

    public BootstrapService(TorControlProtocol torControlProtocol, long timeout) {
        super(EventType.STATUS_CLIENT);
        this.torControlProtocol = torControlProtocol;
        this.timeout = timeout;
    }

    public CompletableFuture<Void> bootstrap() {
        future = Optional.of(CompletableFuture.runAsync(() -> {
                    torControlProtocol.addConnectionEndListener(connectionEndListener);
                    torControlProtocol.addBootstrapEventListener(this);

                    torControlProtocol.takeOwnership();
                    torControlProtocol.resetConf(EmbeddedTorProcess.ARG_OWNER_PID);
                    torControlProtocol.setConfig(DISABLE_NETWORK, "0");

                    try {
                        boolean isSuccess = countDownLatch.await(timeout, TimeUnit.MILLISECONDS);
                        if (isShutdown) {
                            throw new TorBootstrapFailedException("The Tor controller was shut down before Tor " +
                                    "bootstrapped");
                        }
                        if (hasConnectionEnded) {
                            throw new TorBootstrapFailedException("The connection to the Tor control port ended " +
                                    "before Tor bootstrapped");
                        }
                        if (!isSuccess) {
                            throw new TorBootstrapFailedException("Could not bootstrap Tor in " + timeout / 1000 + " seconds");
                        }
                    } catch (InterruptedException e) {
                        log.warn("Thread got interrupted at bootstrap method", e);
                        Thread.currentThread().interrupt(); // Restore interrupted state
                        throw new TorBootstrapFailedException(e);
                    }
                }, MoreExecutors.directExecutor())
                .whenComplete((nil, throwable) -> {
                    torControlProtocol.removeConnectionEndListener(connectionEndListener);
                    torControlProtocol.removeBootstrapEventListener(this);
                }));
        return future.get();
    }

    // Tor exited or closed the connection: the done event cannot arrive any more.
    private void onConnectionEnd() {
        hasConnectionEnded = true;
        countDownLatch.countDown();
    }

    public void shutdown() {
        isShutdown = true;
        torControlProtocol.removeBootstrapEventListener(this);
        if (countDownLatch.getCount() > 0) {
            countDownLatch.countDown();
        }
    }

    @Override
    public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
        log.info("Tor bootstrap event: {}", torBootstrapEvent);
        if (torBootstrapEvent.isDoneEvent()) {
            countDownLatch.countDown();
        }
    }
}
