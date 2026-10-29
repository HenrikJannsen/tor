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

package bisq.gradle.tasks.download;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.gradle.api.logging.Logger;
import org.gradle.api.logging.Logging;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DownloadTaskTest {
    private static final byte[] CONTENT = "the bytes of a bundle".getBytes(StandardCharsets.US_ASCII);
    private static final int CONNECT_TIMEOUT_MILLIS = 2_000;
    private static final int READ_TIMEOUT_MILLIS = 300;
    private static final Logger LOGGER = Logging.getLogger(DownloadTaskTest.class);

    @TempDir
    Path directory;
    private HttpServer server;
    private final CountDownLatch endOfTest = new CountDownLatch(1);

    @AfterEach
    void stopServer() {
        endOfTest.countDown();
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void downloadsTheFile() throws IOException {
        URL url = serve(exchange -> respond(exchange, 200, CONTENT));
        Path file = directory.resolve("bundle.tar.gz");

        DownloadTask.Companion.downloadWithOneRetry(url, file.toFile(), CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, LOGGER);

        assertArrayEquals(CONTENT, Files.readAllBytes(file));
        assertFalse(Files.exists(directory.resolve("bundle.tar.gz.part")));
    }

    @Test
    void triesOnceMoreAfterAFailedAttempt() throws IOException {
        AtomicInteger requests = new AtomicInteger();
        URL url = serve(exchange -> {
            if (requests.incrementAndGet() == 1) {
                respond(exchange, 503, new byte[0]);
            } else {
                respond(exchange, 200, CONTENT);
            }
        });
        Path file = directory.resolve("bundle.tar.gz");

        DownloadTask.Companion.downloadWithOneRetry(url, file.toFile(), CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, LOGGER);

        assertEquals(2, requests.get());
        assertArrayEquals(CONTENT, Files.readAllBytes(file));
    }

    @Test
    void endsAStalledDownloadAtTheReadTimeoutAndKeepsNoPartialFile() throws IOException {
        AtomicInteger requests = new AtomicInteger();
        URL url = serve(exchange -> {
            requests.incrementAndGet();
            exchange.sendResponseHeaders(200, CONTENT.length);
            try (OutputStream body = exchange.getResponseBody()) {
                body.write(CONTENT, 0, 4);
                body.flush();
                endOfTest.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        Path file = directory.resolve("bundle.tar.gz");
        long start = System.nanoTime();

        assertThrows(SocketTimeoutException.class, () -> DownloadTask.Companion.downloadWithOneRetry(url, file.toFile(),
                CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, LOGGER));

        assertTrue((System.nanoTime() - start) / 1_000_000 >= 2 * READ_TIMEOUT_MILLIS);
        assertFalse(Files.exists(file));
        assertFalse(Files.exists(directory.resolve("bundle.tar.gz.part")));
    }

    private interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private URL serve(Handler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/bundle.tar.gz", handler::handle);
        // Each request on a thread of its own, so that a stalled request does not block the next one
        server.setExecutor(command -> new Thread(command).start());
        server.start();
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/bundle.tar.gz").toURL();
    }

    private static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(body);
        }
    }
}
