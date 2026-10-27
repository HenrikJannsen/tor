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

package bisq.network.tor.sandbox;

import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.platform.Platform;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.BaseEncoding;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;

/**
 * The sandy binary that the build embeds as a resource (see {@code resources/sandy/README.md}). Before every start of
 * Tor, Bisq installs it into a directory that Tor cannot write and checks its SHA-256 hash against the embedded
 * {@code SHA256SUMS}.
 */
@Slf4j
public final class SandyBinary {
    private static final String RESOURCE_DIR = "sandy/";
    private static final String SUMS_RESOURCE = RESOURCE_DIR + "SHA256SUMS";

    @VisibleForTesting
    interface Source {
        InputStream open() throws IOException;
    }

    private SandyBinary() {
    }

    /**
     * The name of the embedded binary of the platform, relative to the resource directory, or empty if Bisq does not
     * embed sandy for the platform.
     */
    public static Optional<String> findEmbeddedName(Platform platform) {
        return switch (platform) {
            case LINUX_X86_64 -> Optional.of("linux_x86_64/sandy");
            case LINUX_ARM_64 -> Optional.of("linux_arm64/sandy");
            case MACOS_X86_64 -> Optional.of("macos_x86_64/sandy");
            case MACOS_ARM_64 -> Optional.of("macos_arm64/sandy");
            case WIN_X86_64 -> Optional.of("win_x86_64/sandy.exe");
            default -> Optional.empty();
        };
    }

    /**
     * Installs the sandy binary of the current platform into {@code sandyDirPath} if it is missing or differs from
     * the embedded binary, and verifies its hash.
     *
     * @return the path of the verified binary
     * @throws IOException if this build has no sandy binary for the platform, or if the binary cannot be installed or
     *                     does not match its hash
     */
    public static Path install(Path sandyDirPath, Platform platform) throws IOException {
        String embeddedName = findEmbeddedName(platform)
                .orElseThrow(() -> new IOException("Bisq has no sandy binary for the platform " +
                        platform.getPlatformName() + "."));
        String expectedSha256 = readEmbeddedSums().get(embeddedName);
        if (expectedSha256 == null) {
            throw new IOException("This build of Bisq contains no sandy binary for the platform " +
                    platform.getPlatformName() + ".");
        }
        String fileName = Paths.get(embeddedName).getFileName().toString();
        Path binaryPath = sandyDirPath.resolve(fileName);
        return install(binaryPath, expectedSha256, () -> openResource(RESOURCE_DIR + embeddedName));
    }

    @VisibleForTesting
    static Path install(Path binaryPath, String expectedSha256, Source source) throws IOException {
        if (!hasExpectedContent(binaryPath, expectedSha256)) {
            log.info("Install sandy to {}", binaryPath.toAbsolutePath());
            extract(binaryPath, expectedSha256, source);
        }
        if (!binaryPath.toFile().canExecute() && !binaryPath.toFile().setExecutable(true, true)) {
            throw new IOException("Cannot make sandy executable: " + binaryPath.toAbsolutePath());
        }
        // Check again after the change of the mode, directly before the caller starts it.
        if (!hasExpectedContent(binaryPath, expectedSha256)) {
            throw new IOException("The installed sandy binary does not match its SHA-256 hash: " +
                    binaryPath.toAbsolutePath());
        }
        return binaryPath;
    }

    private static boolean hasExpectedContent(Path binaryPath, String expectedSha256) throws IOException {
        if (!Files.isRegularFile(binaryPath, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        try (InputStream inputStream = Files.newInputStream(binaryPath, LinkOption.NOFOLLOW_LINKS)) {
            return expectedSha256.equals(Sha256Sums.sha256Hex(inputStream));
        }
    }

    private static void extract(Path binaryPath, String expectedSha256, Source source) throws IOException {
        Path dirPath = binaryPath.toAbsolutePath().getParent();
        FileUtils.createDirectories(dirPath);
        Path tempFilePath = Files.createTempFile(dirPath, binaryPath.getFileName().toString(), ".tmp");
        try {
            MessageDigest digest = Sha256Sums.newSha256Digest();
            try (InputStream inputStream = new DigestInputStream(source.open(), digest);
                 OutputStream outputStream = Files.newOutputStream(tempFilePath)) {
                inputStream.transferTo(outputStream);
            }
            String actualSha256 = BaseEncoding.base16().lowerCase().encode(digest.digest());
            if (!expectedSha256.equals(actualSha256)) {
                throw new IOException("The embedded sandy binary does not match its SHA-256 hash. Expected " +
                        expectedSha256 + ", got " + actualSha256);
            }
            if (!tempFilePath.toFile().setExecutable(true, true)) {
                throw new IOException("Cannot make sandy executable: " + tempFilePath.toAbsolutePath());
            }
            if (Files.exists(binaryPath, LinkOption.NOFOLLOW_LINKS) && Files.isDirectory(binaryPath, LinkOption.NOFOLLOW_LINKS)) {
                FileUtils.deleteRecursively(binaryPath);
            }
            Files.move(tempFilePath, binaryPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tempFilePath);
        }
    }

    // Empty if the build packaged no sandy binary
    private static Map<String, String> readEmbeddedSums() throws IOException {
        InputStream sumsInputStream = SandyBinary.class.getClassLoader().getResourceAsStream(SUMS_RESOURCE);
        if (sumsInputStream == null) {
            return Map.of();
        }
        try (InputStream inputStream = sumsInputStream) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            inputStream.transferTo(outputStream);
            return Sha256Sums.parse(outputStream.toString(StandardCharsets.UTF_8));
        }
    }

    private static InputStream openResource(String resourceName) throws IOException {
        InputStream inputStream = SandyBinary.class.getClassLoader().getResourceAsStream(resourceName);
        if (inputStream == null) {
            throw new IOException("Missing resource: " + resourceName);
        }
        return inputStream;
    }
}
