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

import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Function;

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
        torController.shutdown();
        server.close();
    }

    @Test
    void theStartOfTheUploadPublishesTheOnionService() throws Exception {
        connect(1000, command -> command.startsWith("ADD_ONION") ?
                addOnionReply(serviceId) + uploadEvent(serviceId) :
                "250 OK\r\n");

        assertThatCode(() -> torController.publish(onionServiceKey, 9999, 12345)).doesNotThrowAnyException();
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

    static String uploadEvent(String serviceId) {
        return "650 HS_DESC UPLOAD " + serviceId + " UNKNOWN " + HS_DIR + " descriptorId HSDIR_INDEX=index\r\n";
    }
}
