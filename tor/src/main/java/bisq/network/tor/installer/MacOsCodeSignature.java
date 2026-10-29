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

package bisq.network.tor.installer;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The Tor expert bundle for macOS ships its programs and libraries without a code signature; inside Tor Browser the
 * signature of the app covers them. On Apple silicon the kernel kills unsigned arm64 code at its first instruction
 * (SIGKILL, so Tor writes nothing), also outside the sandbox. An ad-hoc signature is enough, so the installer signs every
 * Mach-O file of the bundle that has no signature, and keeps a signature that is there.
 */
@Slf4j
final class MacOsCodeSignature {
    private static final String CODESIGN = "/usr/bin/codesign";
    private static final long TIMEOUT_SEC = 60;

    private MacOsCodeSignature() {
    }

    static void signUnsignedCode(Path bundleDirPath) throws IOException {
        for (Path file : machOFiles(bundleDirPath)) {
            if (run(List.of(CODESIGN, "--verify", file.toString())) != 0) {
                log.info("Sign {} ad hoc", file);
                if (run(List.of(CODESIGN, "--sign", "-", "--force", file.toString())) != 0) {
                    throw new IOException("Cannot sign " + file + " ad hoc with " + CODESIGN);
                }
            }
        }
    }

    // The bundle and its pluggable transports
    static List<Path> machOFiles(Path bundleDirPath) throws IOException {
        try (Stream<Path> files = Files.walk(bundleDirPath, 2)) {
            return files.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(MacOsCodeSignature::isMachO)
                    .sorted()
                    .collect(Collectors.toList());
        }
    }

    /**
     * The magic numbers of thin Mach-O files of either word size and byte order, and of fat (universal) files. A Java
     * class file starts with the magic of a fat file too, followed by its version, so a fat file must name between 1
     * and 19 architectures next, which is how file(1) tells them apart.
     */
    static boolean isMachO(Path file) {
        byte[] header = new byte[8];
        int length;
        try (InputStream inputStream = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            length = inputStream.readNBytes(header, 0, header.length);
        } catch (IOException e) {
            return false;
        }
        if (length < 4) {
            return false;
        }
        return switch (bigEndianInt(header, 0)) {
            case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xbebafeca -> true;
            case 0xcafebabe -> length == header.length && bigEndianInt(header, 4) >= 1 && bigEndianInt(header, 4) < 20;
            default -> false;
        };
    }

    private static int bigEndianInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24) | ((bytes[offset + 1] & 0xff) << 16) | ((bytes[offset + 2] & 0xff) << 8) |
                (bytes[offset + 3] & 0xff);
    }

    private static int run(List<String> command) throws IOException {
        return run(command, TIMEOUT_SEC);
    }

    static int run(List<String> command, long timeoutSec) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        // Read on another thread, so that a command which hangs with its output open still ends at the timeout
        CompletableFuture<String> output = CompletableFuture.supplyAsync(() -> readOutput(process),
                ForkJoinPool.commonPool());
        try {
            if (!process.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IOException(String.join(" ", command) + " did not finish within " + timeoutSec + " s");
            }
            if (process.exitValue() != 0) {
                log.debug("{}: {}", String.join(" ", command),
                        output.completeOnTimeout("", timeoutSec, TimeUnit.SECONDS).join());
            }
            return process.exitValue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("Interrupted while running " + CODESIGN, e);
        }
    }

    private static String readOutput(Process process) {
        try (InputStream inputStream = process.getInputStream()) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            return "";
        }
    }
}
