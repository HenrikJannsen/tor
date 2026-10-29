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
import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.events.listener.HsDescEventListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(30)
class TorControlProtocolEventRegistrationTest {
    private static final int THREADS = 8;
    private static final int ROUNDS = 100;

    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private final ExecutorService executor = Executors.newFixedThreadPool(THREADS);
    private FakeTorControlServer server;

    @AfterEach
    void tearDown() throws Exception {
        executor.shutdownNow();
        torControlProtocol.close();
        server.close();
    }

    @Test
    void everySetEventsNamesTheEventsOfTheRegisteredListeners() throws Exception {
        // While a thread waits for the reply to its SETEVENTS, no other thread may change the listeners. The fake Tor
        // therefore sees the listeners which the command must name.
        List<String> mismatches = new CopyOnWriteArrayList<>();
        server = new FakeTorControlServer(command -> {
            if (command.startsWith("SETEVENTS")) {
                Set<String> registered = torControlProtocol.eventTypesOfListeners();
                if (!eventsOf(command).equals(registered)) {
                    mismatches.add(command + " while the listeners need " + registered);
                }
            }
            return "250 OK\r\n";
        });
        torControlProtocol.initialize(server.getPort());

        List<CompletableFuture<Void>> tasks = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            boolean usesHsDescEvents = i % 2 == 0;
            tasks.add(CompletableFuture.runAsync(() -> {
                for (int round = 0; round < ROUNDS; round++) {
                    if (usesHsDescEvents) {
                        HsDescEventListener listener = new HsDescEventListener(EventType.HS_DESC) {
                            @Override
                            public void onHsDescEvent(HsDescEvent hsDescEvent) {
                            }
                        };
                        torControlProtocol.addHsDescEventListener(listener);
                        torControlProtocol.removeHsDescEventListener(listener);
                    } else {
                        BootstrapEventListener listener = new BootstrapEventListener(EventType.STATUS_CLIENT) {
                            @Override
                            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
                            }
                        };
                        torControlProtocol.addBootstrapEventListener(listener);
                        torControlProtocol.removeBootstrapEventListener(listener);
                    }
                }
            }, executor));
        }
        tasks.forEach(CompletableFuture::join);

        assertThat(mismatches).isEmpty();
        List<String> setEventsCommands = server.getCommands().stream()
                .filter(command -> command.startsWith("SETEVENTS"))
                .collect(Collectors.toList());
        assertThat(setEventsCommands).isNotEmpty();
        assertThat(setEventsCommands.get(setEventsCommands.size() - 1)).isEqualTo("SETEVENTS");
    }

    private static Set<String> eventsOf(String setEventsCommand) {
        Set<String> events = new HashSet<>(Arrays.asList(setEventsCommand.substring("SETEVENTS".length()).trim().split(" ")));
        events.remove("");
        return events;
    }
}
