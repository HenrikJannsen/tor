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

import bisq.network.tor.common.util.StringUtils;
import bisq.network.tor.controller.events.events.EventType;
import bisq.network.tor.controller.events.events.HsDescEvent;
import bisq.network.tor.controller.events.events.HsDescFailedEvent;
import bisq.network.tor.controller.events.listener.FilteredHsDescEventListener;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Slf4j
public class OnionServiceOnlineStateService extends FilteredHsDescEventListener {
    private final TorControlProtocol torControlProtocol;
    private final String onionAddress;
    private final long timeout;
    private final CountDownLatch countDownLatch = new CountDownLatch(1);
    private final Runnable connectionEndListener = this::onConnectionEnd;
    private volatile boolean hasConnectionEnded;
    private boolean isOnline;
    private final ExecutorService executor;

    public OnionServiceOnlineStateService(TorControlProtocol torControlProtocol, String onionAddress, long timeout) {
        super(EventType.HS_DESC, onionAddress, Set.of(HsDescEvent.Action.FAILED, HsDescEvent.Action.RECEIVED));

        this.torControlProtocol = torControlProtocol;
        this.onionAddress = onionAddress;
        this.timeout = timeout;
        String name = "OnionServiceOnlineStateService-" + StringUtils.truncate(onionAddress, 12);
        executor = Executors.newSingleThreadExecutor(new ThreadFactoryBuilder()
                .setNameFormat(name + "-%d")
                .setDaemon(true)
                .setPriority(Thread.NORM_PRIORITY)
                .build());
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
                    if (hasConnectionEnded) {
                        throw new RuntimeException("The connection to the Tor control port ended before the lookup " +
                                "of the onion service completed");
                    }
                    if (!isSuccess) {
                        throw new RuntimeException("Could not get onion address upload completed in " + timeout / 1000 + " seconds");
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

    public void shutdown() {
        torControlProtocol.removeHsDescEventListener(this);
        if (countDownLatch.getCount() > 0) {
            countDownLatch.countDown();
        }
        MoreExecutors.shutdownAndAwaitTermination(executor, 100, TimeUnit.MILLISECONDS);
    }

    @Override
    public void onFilteredEvent(HsDescEvent hsDescEvent) {
        switch (hsDescEvent.getAction()) {
            case FAILED:
                HsDescFailedEvent hsDescFailedEvent = (HsDescFailedEvent) hsDescEvent;
                if (hsDescFailedEvent.getReason().equals("REASON=NOT_FOUND")) {
                    log.info("hsFetch request for {} failed with reason NOT_FOUND", onionAddress);
                    countDownLatch.countDown();
                }
                break;
            case RECEIVED:
                log.info("hsFetch request for {} succeeded", onionAddress);
                isOnline = true;
                countDownLatch.countDown();
                break;
            case UPLOADED:
                break;
        }
    }
}
