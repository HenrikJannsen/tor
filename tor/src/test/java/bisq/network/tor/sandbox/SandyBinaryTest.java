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

import bisq.network.tor.common.platform.Platform;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SandyBinaryTest {
    private static final byte[] CONTENT = "the sandy binary".getBytes(StandardCharsets.UTF_8);

    @Test
    void installsBinaryWhenMissing(@TempDir Path tempDirPath) throws IOException {
        Path binaryPath = tempDirPath.resolve("sandy").resolve("sandy");

        Path installedPath = SandyBinary.install(binaryPath, sha256(CONTENT), () -> new ByteArrayInputStream(CONTENT));

        assertThat(installedPath).isEqualTo(binaryPath);
        assertThat(Files.readAllBytes(binaryPath)).isEqualTo(CONTENT);
        assertThat(binaryPath.toFile().canExecute()).isTrue();
        try (var stream = Files.list(binaryPath.getParent())) {
            assertThat(stream.toList()).containsExactly(binaryPath);
        }
    }

    @Test
    void keepsBinaryWithExpectedHash(@TempDir Path tempDirPath) throws IOException {
        Path binaryPath = tempDirPath.resolve("sandy");
        AtomicInteger numOpened = new AtomicInteger();
        SandyBinary.Source source = () -> {
            numOpened.incrementAndGet();
            return new ByteArrayInputStream(CONTENT);
        };
        SandyBinary.install(binaryPath, sha256(CONTENT), source);

        SandyBinary.install(binaryPath, sha256(CONTENT), source);

        assertThat(numOpened.get()).isEqualTo(1);
    }

    @Test
    void replacesChangedBinary(@TempDir Path tempDirPath) throws IOException {
        Path binaryPath = tempDirPath.resolve("sandy");
        Files.write(binaryPath, "changed by someone else".getBytes(StandardCharsets.UTF_8));

        SandyBinary.install(binaryPath, sha256(CONTENT), () -> new ByteArrayInputStream(CONTENT));

        assertThat(Files.readAllBytes(binaryPath)).isEqualTo(CONTENT);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void replacesSymbolicLink(@TempDir Path tempDirPath) throws IOException {
        Path otherFilePath = tempDirPath.resolve("other");
        Files.write(otherFilePath, CONTENT);
        Path binaryPath = tempDirPath.resolve("sandy");
        Files.createSymbolicLink(binaryPath, otherFilePath);

        SandyBinary.install(binaryPath, sha256(CONTENT), () -> new ByteArrayInputStream(CONTENT));

        assertThat(Files.isSymbolicLink(binaryPath)).isFalse();
        assertThat(Files.readAllBytes(binaryPath)).isEqualTo(CONTENT);
    }

    // A directory at the path of the binary, for example left by another program, is replaced with its content.
    @Test
    void replacesDirectory(@TempDir Path tempDirPath) throws IOException {
        Path binaryPath = tempDirPath.resolve("sandy");
        Files.write(Files.createDirectories(binaryPath.resolve("nested")).resolve("file"), CONTENT);

        SandyBinary.install(binaryPath, sha256(CONTENT), () -> new ByteArrayInputStream(CONTENT));

        assertThat(binaryPath).isRegularFile();
        assertThat(Files.readAllBytes(binaryPath)).isEqualTo(CONTENT);
        try (var stream = Files.list(tempDirPath)) {
            assertThat(stream.toList()).containsExactly(binaryPath);
        }
    }

    @Test
    void refusesEmbeddedBinaryWithWrongHash(@TempDir Path tempDirPath) {
        Path binaryPath = tempDirPath.resolve("sandy");
        byte[] otherContent = "another binary".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> SandyBinary.install(binaryPath, sha256(CONTENT), () -> new ByteArrayInputStream(otherContent)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("does not match its SHA-256 hash");
        assertThat(binaryPath).doesNotExist();
    }

    @Test
    void embedsSandyForTheTorPlatforms() {
        assertThat(SandyBinary.findEmbeddedName(Platform.LINUX_X86_64)).contains("linux_x86_64/sandy");
        assertThat(SandyBinary.findEmbeddedName(Platform.LINUX_ARM_64)).contains("linux_arm64/sandy");
        assertThat(SandyBinary.findEmbeddedName(Platform.MACOS_X86_64)).contains("macos_x86_64/sandy");
        assertThat(SandyBinary.findEmbeddedName(Platform.MACOS_ARM_64)).contains("macos_arm64/sandy");
        assertThat(SandyBinary.findEmbeddedName(Platform.WIN_X86_64)).contains("win_x86_64/sandy.exe");
        assertThat(SandyBinary.findEmbeddedName(Platform.WIN_ARM_64)).isEmpty();
        assertThat(SandyBinary.findEmbeddedName(Platform.ANDROID_ARM_64)).isEmpty();
    }

    @Test
    void refusesPlatformWithoutEmbeddedBinary(@TempDir Path tempDirPath) {
        assertThatThrownBy(() -> SandyBinary.install(tempDirPath, Platform.WIN_ARM_64))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("win_arm64");
    }

    // The build packages the binary of its platform unless -Psandy.package=false.
    @Test
    void anEmbeddedBinaryMatchesTheEmbeddedSums() throws IOException {
        assumeTrue(SandyBinaryTest.class.getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        Map<String, String> sums = Sha256Sums.parse(readResource("sandy/SHA256SUMS"));

        assertThat(sums).hasSize(1);
        String embeddedName = sums.keySet().iterator().next();
        assertThat(Arrays.stream(Platform.values()).map(SandyBinary::findEmbeddedName).flatMap(Optional::stream))
                .contains(embeddedName);
        try (InputStream inputStream = openResource("sandy/" + embeddedName)) {
            assertThat(Sha256Sums.sha256Hex(inputStream)).as(embeddedName).isEqualTo(sums.get(embeddedName));
        }
    }

    private static String sha256(byte[] content) throws IOException {
        return Sha256Sums.sha256Hex(new ByteArrayInputStream(content));
    }

    private static String readResource(String name) throws IOException {
        try (InputStream inputStream = openResource(name)) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static InputStream openResource(String name) {
        InputStream inputStream = SandyBinaryTest.class.getClassLoader().getResourceAsStream(name);
        assertThat(inputStream).as(name).isNotNull();
        return inputStream;
    }
}
