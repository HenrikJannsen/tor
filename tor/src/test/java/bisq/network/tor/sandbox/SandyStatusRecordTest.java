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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SandyStatusRecordTest {
    @TempDir
    Path tempDir;

    @Test
    void readsTheLinesOfTheRecord() throws IOException {
        Path path = Files.writeString(tempDir.resolve("run-status"), "level contained\npid 4711\nexited 1\n");

        SandyStatusRecord record = SandyStatusRecord.read(path).orElseThrow();

        assertThat(record.lines()).containsExactly("level contained", "pid 4711", "exited 1");
        assertThat(record.hasProgramStarted()).isTrue();
        assertThat(record.hasSandyFailed()).isFalse();
        assertThat(record).hasToString("level contained, pid 4711, exited 1");
    }

    // sandy creates the file at the start of the run, so a missing file means that sandy stopped before.
    @Test
    void aMissingFileIsNoRecord() throws IOException {
        assertThat(SandyStatusRecord.read(tempDir.resolve("run-status"))).isEmpty();
    }

    @Test
    void anEmptyFileIsAnEmptyRecord() throws IOException {
        Path path = Files.writeString(tempDir.resolve("run-status"), "");

        SandyStatusRecord record = SandyStatusRecord.read(path).orElseThrow();

        assertThat(record.lines()).isEmpty();
        assertThat(record).hasToString("empty");
    }

    @Test
    void aFileWhichSandyCannotHaveWrittenIsRefused() throws IOException {
        Path path = Files.writeString(tempDir.resolve("run-status"), "failed\n".repeat(1000));

        assertThatThrownBy(() -> SandyStatusRecord.read(path))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("more than 4096 bytes");
    }
}
