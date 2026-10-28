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
import bisq.network.tor.controller.events.events.HsDescFailedEvent;
import bisq.network.tor.controller.events.listener.FilteredHsDescEventListener;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

@Slf4j
public class OnionServiceOnlineStateService extends FilteredHsDescEventListener {
    private static final AtomicInteger INSTANCE_COUNTER = new AtomicInteger();

    private final TorControlProtocol torControlProtocol;
    private final String onionAddress;
    private final long timeout;
    private final CountDownLatch countDownLatch = new CountDownLatch(1);
    private final Runnable connectionEndListener = this::onConnectionEnd;
    // The controller closes the connection before it shuts the service down, so an end of the connection during the
    // shutdown of the controller is that shutdown.
    private final BooleanSupplier isControllerShutDown;
    private volatile boolean isShutdown;
    private volatile boolean hasConnectionEnded;
    // The result of the lookup, written by the first HS_DESC event before it opens the latch
    private boolean isOnline;
    // The end of the message of a lookup which Tor could not make
    private Optional<String> failureReason = Optional.empty();
    private final ExecutorService executor;

    public OnionServiceOnlineStateService(TorControlProtocol torControlProtocol, String onionAddress, long timeout) {
        this(torControlProtocol, onionAddress, timeout, () -> false);
    }

    OnionServiceOnlineStateService(TorControlProtocol torControlProtocol,
                                   String onionAddress,
                                   long timeout,
                                   BooleanSupplier isControllerShutDown) {
        super(EventType.HS_DESC, onionAddress, Set.of(HsDescEvent.Action.FAILED, HsDescEvent.Action.RECEIVED));

        this.torControlProtocol = torControlProtocol;
        this.onionAddress = onionAddress;
        this.timeout = timeout;
        this.isControllerShutDown = isControllerShutDown;
        executor = Executors.newSingleThreadExecutor(createThreadFactory());
    }

    /**
     * The thread name carries a counter instead of the onion address: it appears in every log line of the thread, and
     * a log which a user shares must not name the peers of the user.
     */
    @VisibleForTesting
    static ThreadFactory createThreadFactory() {
        return new ThreadFactoryBuilder()
                .setNameFormat("OnionServiceOnlineStateService-" + INSTANCE_COUNTER.incrementAndGet() + "-%d")
                .setDaemon(true)
                .setPriority(Thread.NORM_PRIORITY)
                .build();
    }

    public CompletableFuture<Boolean> isOnionServiceOnlineAsync() {
        return CompletableFuture.supplyAsync(() -> {
                    torControlProtocol.addConnectionEndListener(connectionEndListener);
                    torControlProtocol.addHsDescEventListener(this);

                    String serviceId = onionAddress.replace(".onion", "");
                    torControlProtocol.hsFetch(serviceId);

                    boolean isSuccess;
                    try {
                        isSuccess = countDownLatch.await(timeout, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt(); // Restore interrupted state
                        throw new RuntimeException(e);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    if (isShutdown || isControllerShutDown.getAsBoolean()) {
                        throw new RuntimeException("The Tor controller was shut down before the lookup of the onion " +
                                "service completed");
                    }
                    if (hasConnectionEnded) {
                        throw new RuntimeException("The connection to the Tor control port ended before the lookup " +
                                "of the onion service completed");
                    }
                    if (!isSuccess) {
                        throw new RuntimeException("Tor did not report the result of the lookup of the onion " +
                                "service within " + timeout / 1000 + " seconds");
                    }
                    if (failureReason.isPresent()) {
                        throw new RuntimeException("Tor could not look up the onion service" + failureReason.get());
                    }

                    return isOnline;
                }, executor)
                .whenComplete((isOnline, throwable) -> {
                    try {
                        torControlProtocol.removeConnectionEndListener(connectionEndListener);
                        removeHsDescEventListenerQuietly();
                    } finally {
                        executor.shutdown();
                    }
                });
    }

    // The result of the lookup stands when Tor does not confirm the SETEVENTS of the removal: an exception here would
    // replace it. Tor then reports HS_DESC events which no listener needs.
    private void removeHsDescEventListenerQuietly() {
        try {
            torControlProtocol.removeHsDescEventListener(this);
        } catch (RuntimeException e) {
            log.warn("Could not remove the event listener of an onion service lookup", e);
        }
    }

    // Tor exited or closed the connection: the result of the lookup cannot arrive any more.
    private void onConnectionEnd() {
        hasConnectionEnded = true;
        countDownLatch.countDown();
    }

    // The lookup fails then: without the flag, the open latch would answer "offline". The lookup, which the count down
    // ends, removes its listeners when it completes.
    public void shutdown() {
        isShutdown = true;
        if (countDownLatch.getCount() > 0) {
            countDownLatch.countDown();
        }
        MoreExecutors.shutdownAndAwaitTermination(executor, 100, TimeUnit.MILLISECONDS);
    }

    /**
     * Tor fetches the descriptor from one HSDir per HSFETCH, so the first result is the answer. NOT_FOUND means that the
     * service is offline. Another reason, for example QUERY_NO_HSDIR or QUERY_RATE_LIMITED, means that Tor could not
     * look it up, so the lookup fails at once instead of waiting for its timeout. The events arrive on the one thread of
     * the reader.
     */
    @Override
    public void onFilteredEvent(HsDescEvent hsDescEvent) {
        if (countDownLatch.getCount() == 0) {
            return;
        }
        switch (hsDescEvent.getAction()) {
            case FAILED:
                Optional<String> reason = ((HsDescFailedEvent) hsDescEvent).getReason();
                // Debug level: the address of a peer must not appear in a shared log.
                log.debug("hsFetch request for {} failed with reason {}", onionAddress, reason.orElse("none"));
                if (!reason.equals(Optional.of("NOT_FOUND"))) {
                    failureReason = Optional.of(reason
                            .map(value -> ". " + TorControlLogFormat.quoteOfTor("REASON=" + value))
                            .orElse(" and named no reason"));
                }
                countDownLatch.countDown();
                break;
            case RECEIVED:
                log.debug("hsFetch request for {} succeeded", onionAddress);
                isOnline = true;
                countDownLatch.countDown();
                break;
            default:
                break;
        }
    }
}
