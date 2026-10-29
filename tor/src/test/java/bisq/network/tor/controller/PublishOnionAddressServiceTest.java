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

import bisq.network.tor.controller.events.events.HsDescEvent;
import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.collect.Sets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(10)
class PublishOnionAddressServiceTest {
    private static final String HS_DIR = "$0123456789ABCDEF0123456789ABCDEF01234567";

    private final OnionServiceKey onionServiceKey = TestKeys.randomOnionServiceKey();
    private final String serviceId = onionServiceKey.getOnionAddress().replace(".onion", "");
    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        if (torController != null) {
            torController.shutdown();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    void theEndOfTheFirstUploadPublishesTheOnionService() throws Exception {
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                addOnionReply(serviceId) + uploadEvents(serviceId) :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
    }

    // At the start of an upload no HSDir has the descriptor, so a peer could not find the onion service. Before, the
    // start of the upload completed the publication.
    @Test
    void theStartOfAnUploadDoesNotPublishTheOnionService() throws Exception {
        connect(300, command -> command.startsWith("ADD_ONION") ?
                addOnionReply(serviceId) + uploadStartEvent(serviceId) :
                "250 OK\r\n");

        assertThatThrownBy(() -> torController.publish(onionServiceKey, 9999, 12345))
                .hasRootCauseInstanceOf(HsDescUploadFailedException.class)
                .hasMessageContaining("upload completed in 300 ms");
        assertThat(server.getCommands()).contains("DEL_ONION " + serviceId);
    }

    @Test
    void onlyTheEventsOfAStoredDescriptorOrOfAShortenedUploadCompleteThePublication() {
        String fullUpload = "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN " + HS_DIR + " descriptorId HSDIR_INDEX=index";
        String shortenedUpload = "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN redacted redacted";

        assertThat(PublishOnionAddressService.completesThePublication(event(fullUpload))).isFalse();
        assertThat(PublishOnionAddressService.completesThePublication(event(shortenedUpload))).isTrue();
        assertThat(PublishOnionAddressService.completesThePublication(
                event("650 HS_DESC UPLOADED " + serviceId + " UNKNOWN " + HS_DIR))).isTrue();
        assertThat(PublishOnionAddressService.completesThePublication(
                event("650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted"))).isTrue();
    }

    // onion-grater of Whonix since September 2024: UPLOAD as Tor sends it, UPLOADED with the HSDir redacted
    @Test
    void theRedactedEndOfAnUploadOfCurrentOnionGraterProfilesPublishesTheOnionService() throws Exception {
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                "250 OK\r\n" + uploadStartEvent(serviceId) +
                        "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted\r\n" :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
    }

    @Test
    void theEndOfAnUploadAlsoPublishesTheOnionService() throws Exception {
        // A filtering control port may deliver only UPLOADED, here with a redacted HSDir as onion-grater on Whonix does
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                "250 OK\r\n" +
                        "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN redacted\r\n" :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
    }

    @Test
    void theShortenedUploadOfOldOnionGraterProfilesPublishesTheOnionService() throws Exception {
        // Onion-grater profiles of Whonix before September 2024 deliver UPLOAD without its optional fields, which the
        // parser read by position and dropped before. There the publication completes at UPLOAD.
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                "250 OK\r\n650 HS_DESC UPLOAD " + serviceId + " UNKNOWN redacted redacted\r\n" :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
    }

    // Tor names the onion address in lower case. Before, the key of an address in upper case failed as the key of
    // another onion address, and its published onion service was removed.
    @Test
    void anOnionAddressInUpperCaseIsPublished() throws Exception {
        OnionServiceKey upperCaseKey = new OnionServiceKey(onionServiceKey.getOnionAddress().toUpperCase(Locale.ROOT),
                onionServiceKey.getBase64SecretScalar());
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                addOnionReply(serviceId) + uploadEvents(serviceId) :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(upperCaseKey, 9999, 12345)).doesNotThrowAnyException();
        assertThat(server.getCommands()).noneMatch(command -> command.startsWith("DEL_ONION"));
    }

    @Test
    void aMissingUploadFailsAndRemovesTheOnionService() throws Exception {
        connect(200, command -> command.startsWith("ADD_ONION") ? addOnionReply(serviceId) : "250 OK\r\n");

        assertThatThrownBy(() -> torController.publish(onionServiceKey, 9999, 12345))
                .hasRootCauseInstanceOf(HsDescUploadFailedException.class);
        assertThat(server.getCommands()).contains("DEL_ONION " + serviceId);
    }

    @Test
    void aShutdownDuringTheWaitFailsThePublication() throws Exception {
        connect(5000, command -> command.startsWith("ADD_ONION") ? addOnionReply(serviceId) : "250 OK\r\n");

        CompletableFuture<Void> publication = torController.publishAsync(onionServiceKey, 9999, 12345);
        waitForCommand("ADD_ONION");
        torController.shutdown();

        assertThatThrownBy(publication::join)
                .isInstanceOf(CompletionException.class)
                .hasCauseInstanceOf(HsDescUploadFailedException.class);
    }

    @Test
    void theEndOfTheConnectionFailsThePublicationAtOnce() throws Exception {
        // Tor exits after it accepted ADD_ONION, long before the upload timeout
        connect(10_000, command -> command.startsWith("ADD_ONION") ? addOnionReply(serviceId) : "250 OK\r\n");
        server.closeConnectionAfter("ADD_ONION");

        long start = System.currentTimeMillis();
        assertThatThrownBy(() -> torController.publish(onionServiceKey, 9999, 12345))
                .hasRootCauseInstanceOf(HsDescUploadFailedException.class)
                .hasMessageContaining("ended");
        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
    }

    @Test
    void theShutdownEndsAtOnceWhenTorDoesNotAnswer() throws Exception {
        // Tor answers the SETEVENTS of the registration, and nothing after the ADD_ONION
        AtomicInteger setEventsCommands = new AtomicInteger();
        connect(10_000, command -> {
            if (command.startsWith("ADD_ONION")) {
                return addOnionReply(serviceId);
            }
            if (command.startsWith("SETEVENTS") && setEventsCommands.incrementAndGet() > 1) {
                return "";
            }
            return "250 OK\r\n";
        });
        CompletableFuture<Void> publication = torController.publishAsync(onionServiceKey, 9999, 12345);
        waitForCommand("ADD_ONION");

        long start = System.currentTimeMillis();
        torController.shutdown();

        assertThat(System.currentTimeMillis() - start).isLessThan(5000);
        assertThatThrownBy(publication::join).hasCauseInstanceOf(HsDescUploadFailedException.class);
    }

    @Test
    void anInterruptedCallerOfPublishReturnsAtOnce() throws Exception {
        connect(10_000, command -> command.startsWith("ADD_ONION") ? addOnionReply(serviceId) : "250 OK\r\n");
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread caller = new Thread(() -> {
            try {
                torController.publish(onionServiceKey, 9999, 12345);
            } catch (InterruptedException e) {
                interrupted.set(true);
            } catch (RuntimeException ignore) {
                // The publication failed otherwise
            }
        });
        caller.start();
        waitForCommand("ADD_ONION");

        caller.interrupt();
        caller.join(5000);

        assertThat(caller.isAlive()).isFalse();
        assertThat(interrupted).isTrue();
    }

    @Test
    void aFailedPublicationIsNotReused() throws Exception {
        connect(1000, command -> command.startsWith("ADD_ONION") ? "550 Onion address collision\r\n" : "250 OK\r\n");

        for (int attempt = 0; attempt < 2; attempt++) {
            assertThatThrownBy(() -> torController.publish(onionServiceKey, 9999, 12345))
                    .hasRootCauseInstanceOf(ControlCommandFailedException.class);
        }

        assertThat(server.getCommands()).filteredOn(command -> command.startsWith("ADD_ONION")).hasSize(2);
    }

    @Test
    void aRefusedRemovalOfTheListenerKeepsThePublicationAndEndsItsThread() throws Exception {
        // Tor confirms the SETEVENTS of the registration and refuses the one of the removal.
        AtomicInteger setEventsCommands = new AtomicInteger();
        connect(1000, command -> {
            if (command.startsWith("ADD_ONION")) {
                return addOnionReply(serviceId) + uploadEvents(serviceId);
            }
            if (command.startsWith("SETEVENTS") && setEventsCommands.incrementAndGet() > 1) {
                return "552 Unrecognized event\r\n";
            }
            return "250 OK\r\n";
        });
        Set<Thread> threadsBefore = liveThreadsNamed("PublishOnionAddressService");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();

        assertThat(setEventsCommands).hasValue(2);
        assertAllEnd(Sets.difference(liveThreadsNamed("PublishOnionAddressService"), threadsBefore));
    }

    static Set<Thread> liveThreadsNamed(String namePrefix) {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().startsWith(namePrefix) && thread.isAlive())
                .collect(Collectors.toSet());
    }

    static void assertAllEnd(Set<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) {
            thread.join(5000);
            assertThat(thread.isAlive()).as("thread %s ended", thread.getName()).isFalse();
        }
    }

    @Test
    void aRetryAfterAnInterruptWaitsForThePublicationWhichGoesOn() throws Exception {
        connectToATorWhichUploadsOnGetInfo();
        interruptAPublicationAfterItsAddOnion();

        CompletableFuture<Void> retry = torController.publishAsync(onionServiceKey, 9999, 12345);
        assertThat(retry).isNotDone();
        torController.getTorVersion();

        assertThatCode(retry::join).doesNotThrowAnyException();
        assertThat(server.getCommands()).filteredOn(command -> command.startsWith("ADD_ONION")).hasSize(1);
    }

    @Test
    void aRetryAfterTheInterruptedPublicationSucceededSendsNoSecondAddOnion() throws Exception {
        connectToATorWhichUploadsOnGetInfo();
        interruptAPublicationAfterItsAddOnion();
        torController.getTorVersion();
        // The publication removes its listener when it has succeeded.
        waitUntil(() -> server.getCommands().stream().filter(command -> command.startsWith("SETEVENTS")).count() == 2);

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
        assertThat(server.getCommands()).filteredOn(command -> command.startsWith("ADD_ONION")).hasSize(1);
    }

    // Tor accepts the first ADD_ONION, starts the upload when the test sends GETINFO, and refuses a second ADD_ONION of
    // the address, which it keeps.
    private void connectToATorWhichUploadsOnGetInfo() throws Exception {
        AtomicInteger addOnionCommands = new AtomicInteger();
        connect(10_000, command -> {
            if (command.startsWith("ADD_ONION")) {
                return addOnionCommands.incrementAndGet() == 1 ?
                        addOnionReply(serviceId) :
                        "550 Onion address collision\r\n";
            }
            if (command.equals("GETINFO version")) {
                return "250-version=0.4.9.14\r\n250 OK\r\n" + uploadEvents(serviceId);
            }
            return "250 OK\r\n";
        });
    }

    private void interruptAPublicationAfterItsAddOnion() throws InterruptedException {
        AtomicBoolean interrupted = new AtomicBoolean();
        Thread caller = new Thread(() -> {
            try {
                torController.publish(onionServiceKey, 9999, 12345);
            } catch (InterruptedException e) {
                interrupted.set(true);
            }
        });
        caller.start();
        waitForCommand("ADD_ONION");
        caller.interrupt();
        caller.join(5000);
        assertThat(interrupted).isTrue();
    }

    private static void waitUntil(BooleanSupplier condition) throws InterruptedException {
        while (!condition.getAsBoolean()) {
            Thread.sleep(10);
        }
    }

    @Test
    void aShutDownControllerPublishesNothing() throws Exception {
        connect(1000, command -> "250 OK\r\n");
        torController.shutdown();

        assertThatThrownBy(() -> torController.publish(onionServiceKey, 9999, 12345))
                .isInstanceOf(HsDescUploadFailedException.class);
    }

    private void connect(int hsUploadTimeout, Function<String, String> replyByCommand) throws Exception {
        server = new FakeTorControlServer(replyByCommand);
        torController = new TorController(1000, hsUploadTimeout);
        torController.initialize(server.getPort());
    }

    private void waitForCommand(String commandStart) throws InterruptedException {
        while (server.getCommands().stream().noneMatch(command -> command.startsWith(commandStart))) {
            Thread.sleep(10);
        }
    }

    static String addOnionReply(String serviceId) {
        return "250-ServiceID=" + serviceId + "\r\n250 OK\r\n";
    }

    // Tor starts the upload of the descriptor to an HSDir, and reports when the HSDir has stored it.
    static String uploadEvents(String serviceId) {
        return uploadStartEvent(serviceId) + "650 HS_DESC UPLOADED " + serviceId + " UNKNOWN " + HS_DIR + "\r\n";
    }

    private static String uploadStartEvent(String serviceId) {
        return "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN " + HS_DIR + " descriptorId HSDIR_INDEX=index\r\n";
    }

    private static HsDescEvent event(String line) {
        return HsDescEventParser.tryParse(line.split(" ")).orElseThrow();
    }
}
