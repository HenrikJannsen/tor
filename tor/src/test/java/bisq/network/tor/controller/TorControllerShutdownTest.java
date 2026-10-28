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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(20)
class TorControllerShutdownTest {
    private TorController torController;
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        torController.shutdown();
        server.close();
    }

    @Test
    void theShutdownEndsAtOnceWhileACommandWaitsForItsReply() throws Exception {
        // The command holds the lock of the control protocol while it waits for the reply, here for 60 seconds. The
        // shutdown must neither wait for the lock nor for the reply.
        server = new FakeTorControlServer(command -> "");
        torController = new TorController(1000, 1000);
        torController.initialize(server.getPort());
        Thread caller = new Thread(torController::getTorVersion);
        caller.start();
        while (!server.getCommands().contains("GETINFO version")) {
            Thread.sleep(10);
        }

        long start = System.currentTimeMillis();
        torController.shutdown();
        caller.join(5000);

        assertThat(System.currentTimeMillis() - start).isLessThan(2000);
        assertThat(caller.isAlive()).isFalse();
    }
}
