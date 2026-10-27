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
import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorControlReaderTest {
    @Test
    void malformedEventsDoNotStopTheReader() {
        List<TorBootstrapEvent> events = new CopyOnWriteArrayList<>();
        TorControlReader reader = new TorControlReader();
        reader.addBootstrapEventListener(new BootstrapEventListener(EventType.STATUS_CLIENT) {
            @Override
            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
                events.add(torBootstrapEvent);
            }
        });
        String lines = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=x TAG=a SUMMARY=\"b\"\r\n" +
                "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=5 TAG=a S\r\n" +
                "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n" +
                "250 OK\r\n";

        reader.start(new ByteArrayInputStream(lines.getBytes(StandardCharsets.US_ASCII)));

        assertThat(reader.readLine()).isEqualTo("250 OK");
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getProgress()).isEqualTo(100);
    }

    @Test
    void aFailingListenerDoesNotKeepTheEventFromTheOtherListeners() {
        List<TorBootstrapEvent> events = new CopyOnWriteArrayList<>();
        TorControlReader reader = new TorControlReader();
        reader.addBootstrapEventListener(new BootstrapEventListener(EventType.STATUS_CLIENT) {
            @Override
            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
                throw new IllegalStateException("A listener fails");
            }
        });
        reader.addBootstrapEventListener(new BootstrapEventListener(EventType.STATUS_CLIENT) {
            @Override
            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
                events.add(torBootstrapEvent);
            }
        });
        String lines = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n" +
                "250 OK\r\n";

        reader.start(new ByteArrayInputStream(lines.getBytes(StandardCharsets.US_ASCII)));

        assertThat(reader.readLine()).isEqualTo("250 OK");
        assertThat(events).hasSize(1);
    }

    @Test
    void theDataOfAReplyIsNotTakenForEvents() {
        // control-spec: the data of a "250+" line follows until a line with a single dot. A data line can start with
        // 650, for example a line of a document, and is still part of the reply.
        List<TorBootstrapEvent> events = new CopyOnWriteArrayList<>();
        TorControlReader reader = new TorControlReader();
        reader.addBootstrapEventListener(new BootstrapEventListener(EventType.STATUS_CLIENT) {
            @Override
            public void onBootstrapStatusEvent(TorBootstrapEvent torBootstrapEvent) {
                events.add(torBootstrapEvent);
            }
        });
        String doneEvent = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n";
        String lines = "250+x=\r\n" + doneEvent + ".\r\n250 OK\r\n" + doneEvent + "250 OK\r\n";

        reader.start(new ByteArrayInputStream(lines.getBytes(StandardCharsets.US_ASCII)));

        assertThat(reader.readLine()).isEqualTo("250+x=");
        assertThat(reader.readLine()).startsWith("650 STATUS_CLIENT");
        assertThat(reader.readLine()).isEqualTo(".");
        assertThat(reader.readLine()).isEqualTo("250 OK");
        // The event after the data is still an event
        assertThat(reader.readLine()).isEqualTo("250 OK");
        assertThat(events).hasSize(1);
    }

    @Test
    void theDataOfAnEventBelongsToNoCommand() {
        TorControlReader reader = new TorControlReader();
        String lines = "650+NEWCONSENSUS\r\n250 OK\r\n.\r\n250 OK\r\n";

        reader.start(new ByteArrayInputStream(lines.getBytes(StandardCharsets.US_ASCII)));

        assertThat(reader.readLine()).isEqualTo("250 OK");
        assertThatThrownBy(reader::readLine).isInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void theEndOfTheStreamWakesUpWaitingCallers() {
        TorControlReader reader = new TorControlReader();

        reader.start(new ByteArrayInputStream("250 OK\r\n".getBytes(StandardCharsets.US_ASCII)));

        assertThat(reader.readLine()).isEqualTo("250 OK");
        assertThatThrownBy(reader::readLine).isInstanceOf(ControlCommandFailedException.class);
        assertThatThrownBy(reader::readLine).isInstanceOf(ControlCommandFailedException.class);
    }

    @Test
    void aMissingReplyEndsTheWait() throws IOException {
        TorControlReader reader = new TorControlReader();
        // A connection that stays open without a reply
        reader.start(new PipedInputStream(new PipedOutputStream()));

        assertThatThrownBy(() -> reader.readLine(100))
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("did not reply");
        reader.close();
    }
}
