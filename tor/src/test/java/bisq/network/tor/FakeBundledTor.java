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

package bisq.network.tor;

import bisq.network.tor.controller.FakeTorControlServer;
import bisq.network.tor.installer.TorBundleMarker;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * A Tor bundle whose tor is a shell script, so that a test runs the embedded start of TorService without a Tor. The
 * script records its arguments and its process ID and waits until it is stopped. Once it runs,
 * {@link #answerControlPort} answers on the control port of the torrc like a Tor which bootstraps at once.
 */
final class FakeBundledTor implements AutoCloseable {
    static final String TOR_VERSION = "0.4.9.14";
    static final String DONE_EVENT = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n";

    private final Path torDir;
    private final Path binDir;
    private final List<FakeTorControlServer> controlServers = new ArrayList<>();
    private final List<Long> processIds = new ArrayList<>();

    private FakeBundledTor(Path torDir) {
        this.torDir = torDir;
        this.binDir = torDir.resolve("bin");
    }

    /**
     * Installs the fake bundle into the Tor directory of a TorService.
     */
    static FakeBundledTor install(Path torDir) throws IOException {
        var fakeTor = new FakeBundledTor(torDir);
        Files.createDirectories(fakeTor.binDir);
        // With a data directory the start migrates no older layout, which would read the bundle of the jar.
        Files.createDirectories(torDir.resolve("data"));
        TorBundleMarker.markAsInstalled(fakeTor.binDir);
        // Tor runs in the binary directory. The process ID file appears last and whole.
        Path tor = fakeTor.binDir.resolve("tor");
        Files.writeString(tor, """
                #!/bin/sh
                printf '%s\\n' "$@" > fake-tor.args
                echo $$ > fake-tor.pid.tmp
                mv fake-tor.pid.tmp fake-tor.pid
                exec sleep 60
                """);
        Files.setPosixFilePermissions(tor, PosixFilePermissions.fromString("rwx------"));
        return fakeTor;
    }

    /**
     * Waits until TorService has started the fake tor of its next start.
     *
     * @return the process ID of the fake tor
     */
    long awaitStart() throws IOException, InterruptedException {
        Path processIdFile = binDir.resolve("fake-tor.pid");
        while (true) {
            if (Files.exists(processIdFile)) {
                long processId = Long.parseLong(Files.readString(processIdFile).trim());
                if (!processIds.contains(processId)) {
                    processIds.add(processId);
                    return processId;
                }
            }
            Thread.sleep(10);
        }
    }

    boolean hasStarted() {
        return Files.exists(binDir.resolve("fake-tor.pid"));
    }

    // Only a process which this JVM started, so that a reused process ID cannot count
    static boolean isRunning(long processId) {
        return ProcessHandle.current().descendants()
                .anyMatch(process -> process.pid() == processId && process.isAlive());
    }

    List<String> arguments() throws IOException {
        return Files.readAllLines(binDir.resolve("fake-tor.args"));
    }

    FakeTorControlServer answerControlPort() throws IOException {
        return answerControlPort(Map.of());
    }

    /**
     * Answers on the control port of the torrc of the started fake tor.
     *
     * @param repliesByCommandStart replies which replace those of a Tor that accepts the password of the torrc and
     *                              bootstraps at once
     */
    FakeTorControlServer answerControlPort(Map<String, Supplier<String>> repliesByCommandStart) throws IOException {
        String torrc = Files.readString(torDir.resolve("torrc"));
        int controlPort = Integer.parseInt(valueOf(torrc, "ControlPort").replace("127.0.0.1:", ""));
        String socksListener = valueOf(torrc, "SocksPort");
        String hashedControlPassword = valueOf(torrc, "HashedControlPassword");
        FakeTorControlServer controlServer = FakeTorControlServer.onPort(controlPort, command ->
                repliesByCommandStart.entrySet().stream()
                        .filter(entry -> command.startsWith(entry.getKey()))
                        .map(entry -> entry.getValue().get())
                        .findFirst()
                        .orElseGet(() -> reply(command, hashedControlPassword, socksListener)));
        controlServers.add(controlServer);
        return controlServer;
    }

    private static String valueOf(String torrc, String key) {
        return torrc.lines()
                .filter(line -> line.startsWith(key + " "))
                .map(line -> line.substring(key.length() + 1))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("The torrc has no " + key));
    }

    private static String reply(String command, String hashedControlPassword, String socksListener) {
        if (command.startsWith("PROTOCOLINFO")) {
            return "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=HASHEDPASSWORD\r\n250-VERSION Tor=\"" + TOR_VERSION +
                    "\"\r\n250 OK\r\n";
        }
        if (command.equals("GETCONF HashedControlPassword")) {
            return "250 HashedControlPassword=" + hashedControlPassword + "\r\n";
        }
        if (command.startsWith("SETCONF DisableNetwork")) {
            return "250 OK\r\n" + DONE_EVENT;
        }
        if (command.equals("GETINFO net/listeners/socks")) {
            return "250-net/listeners/socks=\"" + socksListener + "\"\r\n250 OK\r\n";
        }
        if (command.equals("GETINFO version")) {
            return "250-version=" + TOR_VERSION + "\r\n250 OK\r\n";
        }
        if (command.startsWith("GETINFO")) {
            return "552 Unrecognized key\r\n";
        }
        return "250 OK\r\n";
    }

    @Override
    public void close() throws Exception {
        // A failed test can leave the fake tor running.
        ProcessHandle.current().descendants()
                .filter(process -> processIds.contains(process.pid()))
                .forEach(ProcessHandle::destroyForcibly);
        for (FakeTorControlServer controlServer : controlServers) {
            controlServer.close();
        }
    }
}
