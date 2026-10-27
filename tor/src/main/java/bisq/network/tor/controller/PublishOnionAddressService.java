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
import bisq.network.tor.controller.events.listener.FilteredHsDescEventListener;
import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Slf4j
public class PublishOnionAddressService extends FilteredHsDescEventListener {
    private final TorControlProtocol torControlProtocol;
    private final int timeout;
    private final OnionServiceKey onionServiceKey;
    private final CountDownLatch countDownLatch = new CountDownLatch(1);
    private final Runnable connectionEndListener = this::onConnectionEnd;
    private volatile boolean isShutdown;
    private volatile boolean hasConnectionEnded;

    public PublishOnionAddressService(TorControlProtocol torControlProtocol, int timeout, OnionServiceKey onionServiceKey) {
        super(EventType.HS_DESC, onionServiceKey.getOnionAddress(), Set.of(HsDescEvent.Action.UPLOAD));

        this.torControlProtocol = torControlProtocol;
        this.timeout = timeout;
        this.onionServiceKey = onionServiceKey;
    }

    public CompletableFuture<Void> publish(int onionServicePort, int localPort) {
        ExecutorService executor = Executors.newSingleThreadExecutor(new ThreadFactoryBuilder()
                .setNameFormat("PublishOnionAddressService")
                .setDaemon(true)
                .setPriority(Thread.NORM_PRIORITY)
                .build());
        return CompletableFuture.runAsync(() -> {
                    torControlProtocol.addConnectionEndListener(connectionEndListener);
                    torControlProtocol.addHsDescEventListener(this);

                    String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
                    torControlProtocol.addOnion(onionServiceKey, onionServicePort, localPort);

                    try {
                        awaitUpload();
                    } catch (RuntimeException e) {
                        // Tor keeps the onion service until the control connection ends. A new publication of the
                        // onion address would fail with "550 Onion address collision".
                        removeOnionServiceQuietly(serviceId);
                        throw e;
                    }
                }, executor)
                .whenComplete((nil, throwable) -> {
                    try {
                        torControlProtocol.removeConnectionEndListener(connectionEndListener);
                        removeHsDescEventListenerQuietly();
                    } finally {
                        executor.shutdown();
                    }
                });
    }

    // The result of the publication stands when Tor does not confirm the SETEVENTS of the removal: an exception here
    // would replace it. Tor then reports HS_DESC events which no listener needs.
    private void removeHsDescEventListenerQuietly() {
        try {
            torControlProtocol.removeHsDescEventListener(this);
        } catch (RuntimeException e) {
            log.warn("Could not remove the event listener of a publication", e);
        }
    }

    // Tor exited or closed the connection: the upload event cannot arrive any more.
    private void onConnectionEnd() {
        hasConnectionEnded = true;
        countDownLatch.countDown();
    }

    private void awaitUpload() {
        boolean isSuccess;
        try {
            isSuccess = countDownLatch.await(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupted state
            throw new HsDescUploadFailedException(e);
        } catch (Exception e) {
            throw new HsDescUploadFailedException(e);
        }
        if (isShutdown) {
            throw new HsDescUploadFailedException("The Tor controller was shut down before the onion " +
                    "service was published");
        }
        if (hasConnectionEnded) {
            throw new HsDescUploadFailedException("The connection to the Tor control port ended before the onion " +
                    "service was published");
        }
        if (!isSuccess) {
            throw new HsDescUploadFailedException("Could not get onion address upload completed in " + timeout + " ms");
        }
    }

    private void removeOnionServiceQuietly(String serviceId) {
        if (isShutdown || hasConnectionEnded) {
            // The control connection ends, and Tor removes the onion service with it.
            return;
        }
        try {
            torControlProtocol.delOnion(serviceId);
        } catch (RuntimeException e) {
            log.warn("Could not remove the onion service {}.onion from Tor", serviceId, e);
        }
    }

    public void shutdown() {
        isShutdown = true;
        torControlProtocol.removeHsDescEventListener(this);
        if (countDownLatch.getCount() > 0) {
            countDownLatch.countDown();
        }
    }

    @Override
    public void onFilteredEvent(HsDescEvent hsDescEvent) {
        log.info("Received HsDescEvent: {}", StringUtils.truncate(hsDescEvent, 200));
        if (countDownLatch.getCount() > 0) {
            log.info("Publishing of onion address completed. Event {}", StringUtils.truncate(hsDescEvent, 200));
        }
        countDownLatch.countDown();
    }
}
