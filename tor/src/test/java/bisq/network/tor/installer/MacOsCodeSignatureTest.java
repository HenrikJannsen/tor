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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MacOsCodeSignatureTest {
    /**
     * The installer signs the programs and libraries of the bundle, and of its pluggable transports, but not its data
     * files.
     */
    @Test
    void findsTheMachOFilesOfTheBundle(@TempDir Path bundleDir) throws IOException {
        Path transports = Files.createDirectories(bundleDir.resolve("pluggable_transports"));
        Files.write(bundleDir.resolve("tor"), new byte[]{(byte) 0xcf, (byte) 0xfa, (byte) 0xed, (byte) 0xfe, 7});
        Files.write(bundleDir.resolve("libevent-2.1.7.dylib"),
                new byte[]{(byte) 0xcf, (byte) 0xfa, (byte) 0xed, (byte) 0xfe});
        // A fat (universal) file with 2 architectures, and a Java class file of version 65, which starts alike
        Files.write(transports.resolve("lyrebird"),
                new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 2});
        Files.write(bundleDir.resolve("Main.class"),
                new byte[]{(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 65});
        Files.writeString(bundleDir.resolve("geoip"), "# geoip");
        Files.writeString(transports.resolve("pt_config.json"), "{}");
        Files.write(bundleDir.resolve("short"), new byte[]{(byte) 0xcf, (byte) 0xfa});

        assertThat(MacOsCodeSignature.machOFiles(bundleDir)).containsExactly(
                bundleDir.resolve("libevent-2.1.7.dylib"),
                transports.resolve("lyrebird"),
                bundleDir.resolve("tor"));
    }

    // A command which hangs with its output open must not hang the installation.
    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void endsACommandThatHangsAtTheTimeout() {
        long start = System.nanoTime();

        assertThatThrownBy(() -> MacOsCodeSignature.run(List.of("sleep", "60"), 1))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("did not finish within 1 s");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(30));
    }
}
