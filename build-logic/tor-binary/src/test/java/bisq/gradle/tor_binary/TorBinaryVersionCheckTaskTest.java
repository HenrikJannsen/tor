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

package bisq.gradle.tor_binary;

import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TorBinaryVersionCheckTaskTest {
    @TempDir
    Path tempDir;

    @Test
    void readsTheBuildVersionAndNoOtherVersionString() {
        byte[] executable = executable("Tor 0.1.2.17 and later; upgrade your controller",
                " (on Tor 0.4.9.14 8fe2745aee2c3511)", "Server: tor/1.0 (tor 0.4.9.14)");

        assertEquals(Set.of("0.4.9.14"), TorBinaryVersionCheckTask.Companion.buildVersions(executable));
    }

    @Test
    void readsTheVersionOfAnAlphaRelease() {
        byte[] executable = executable(" (on Tor 0.4.10.1-alpha 0123456789abcdef)");

        assertEquals(Set.of("0.4.10.1-alpha"), TorBinaryVersionCheckTask.Companion.buildVersions(executable));
    }

    @Test
    void acceptsTheVersionOfTheBundle() throws IOException {
        TorBinaryVersionCheckTask task = task(executable(" (on Tor 0.4.9.14 8fe2745aee2c3511)"), "0.4.9.14");

        task.verify();

        assertEquals("0.4.9.14", Files.readString(task.getResultFile().get().getAsFile().toPath()));
    }

    @Test
    void refusesAnotherVersion() throws IOException {
        TorBinaryVersionCheckTask task = task(executable(" (on Tor 0.4.9.13 0123456789abcdef)"), "0.4.9.14");

        GradleException exception = assertThrows(GradleException.class, task::verify);
        assertTrue(exception.getMessage().contains("contains tor 0.4.9.13"), exception.getMessage());
        assertTrue(exception.getMessage().contains("tor.binaryVersion in gradle.properties is 0.4.9.14"),
                exception.getMessage());
    }

    @Test
    void refusesAnExecutableWithoutOrWithSeveralBuildVersions() throws IOException {
        TorBinaryVersionCheckTask withoutVersion = task(executable("Tor 0.1.2.17 and later"), "0.4.9.14");
        assertThrows(GradleException.class, withoutVersion::verify);

        TorBinaryVersionCheckTask withTwoVersions = task(executable(" (on Tor 0.4.9.14 8fe2745aee2c3511)",
                " (on Tor 0.4.9.13 0123456789abcdef)"), "0.4.9.14");
        assertThrows(GradleException.class, withTwoVersions::verify);
    }

    private TorBinaryVersionCheckTask task(byte[] executable, String expectedVersion) throws IOException {
        Project project = ProjectBuilder.builder().withProjectDir(tempDir.toFile()).build();
        Path executablePath = tempDir.resolve("tor");
        Files.write(executablePath, executable);
        TorBinaryVersionCheckTask task = project.getTasks().register("verifyTorBinaryVersion",
                TorBinaryVersionCheckTask.class).get();
        task.getTorExecutable().set(executablePath.toFile());
        task.getExpectedVersion().set(expectedVersion);
        task.getResultFile().set(tempDir.resolve("tor-version.result").toFile());
        return task;
    }

    // Strings between bytes which are not text, as in an executable
    private static byte[] executable(String... strings) {
        ByteArrayOutputStream executable = new ByteArrayOutputStream();
        for (String string : strings) {
            executable.writeBytes(new byte[]{0, 1, (byte) 0xff, 0});
            executable.writeBytes(string.getBytes(StandardCharsets.ISO_8859_1));
        }
        executable.writeBytes(new byte[]{0, (byte) 0x90});
        return executable.toByteArray();
    }
}
