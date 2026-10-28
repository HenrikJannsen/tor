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
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// With the sandbox, the lines on the control connection come from a process which an attacker may control.
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
    void anOversizedLineEndsTheConnection() {
        TorControlReader reader = new TorControlReader();
        String line = "250-" + "x".repeat(TorControlReader.MAX_LINE_LENGTH) + "\r\n";

        reader.start(new ByteArrayInputStream(line.getBytes(StandardCharsets.US_ASCII)));

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

    @Test
    void aFullQueueHoldsTheReaderUntilTheRepliesAreRead() throws Exception {
        // Replies which nobody reads must not use unbounded memory. The reader stops reading from the connection while
        // its queue is full, and it delivers every line in order once the lines are read.
        int numLines = 2000;
        StringBuilder lines = new StringBuilder();
        for (int i = 0; i < numLines; i++) {
            lines.append("250-line").append(i).append('=').append("x".repeat(80)).append("\r\n");
        }
        byte[] bytes = lines.toString().getBytes(StandardCharsets.US_ASCII);
        AtomicLong bytesRead = new AtomicLong();
        InputStream input = new FilterInputStream(new ByteArrayInputStream(bytes)) {
            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                int read = super.read(buffer, offset, length);
                bytesRead.addAndGet(Math.max(read, 0));
                return read;
            }
        };
        TorControlReader reader = new TorControlReader();
        reader.start(input);

        long readBefore;
        do {
            readBefore = bytesRead.get();
            Thread.sleep(200);
        } while (bytesRead.get() != readBefore || readBefore == 0);
        // The queue and the buffer of the reader, far less than all lines
        assertThat(bytesRead.get()).isLessThan(bytes.length / 2);

        for (int i = 0; i < numLines; i++) {
            assertThat(reader.readLine()).startsWith("250-line" + i + "=");
        }
        reader.close();
    }

    @Test
    void theEndOfTheConnectionReachesACallerAlsoWhenTheQueueIsFull() throws InterruptedException {
        // The end of the stream does not fit behind the unread replies. Nobody reads them, so the reader drops them
        // instead of blocking, and a caller learns that the connection has ended.
        StringBuilder lines = new StringBuilder();
        for (int i = 0; i < TorControlReader.MAX_QUEUED_REPLIES; i++) {
            lines.append("250-line").append(i).append("=x\r\n");
        }
        TorControlReader reader = new TorControlReader();
        CountDownLatch connectionEnd = new CountDownLatch(1);
        reader.addConnectionEndListener(connectionEnd::countDown);

        reader.start(new ByteArrayInputStream(lines.toString().getBytes(StandardCharsets.US_ASCII)));

        assertThat(connectionEnd.await(5, TimeUnit.SECONDS)).isTrue();
        assertThatThrownBy(reader::readLine)
                .isInstanceOf(ControlCommandFailedException.class)
                .hasMessageContaining("ended");
    }

    @Test
    void readsLinesWithAndWithoutCarriageReturn() throws IOException {
        StringReader input = new StringReader("250 OK\r\n650 HS_DESC\nlast");

        assertThat(TorControlReader.readBoundedLine(input)).isEqualTo("250 OK");
        assertThat(TorControlReader.readBoundedLine(input)).isEqualTo("650 HS_DESC");
        assertThat(TorControlReader.readBoundedLine(input)).isEqualTo("last");
        assertThat(TorControlReader.readBoundedLine(input)).isNull();
    }
}
