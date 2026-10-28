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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * The status record of a run of sandy, which {@code sandy run --status-file} writes (sandy README.md, "The status
 * record"): {@code level NAME} for a policy with fallback levels, {@code pid N} for the program, {@code exited N} or
 * {@code signaled N} where sandy saw the program end, and {@code failed} when sandy itself failed or refused. sandy
 * creates the file outside every path which the policy lets the program write and never gives the program its
 * descriptor, so Tor can neither write nor remove the record.
 *
 * @param lines the lines of the record, without blank lines
 */
public record SandyStatusRecord(List<String> lines) {
    // A record has a few short lines. A larger file is not one that sandy wrote.
    private static final int MAX_BYTES = 4096;
    private static final String PID_PREFIX = "pid ";
    private static final String FAILED = "failed";

    public SandyStatusRecord {
        lines = List.copyOf(lines);
    }

    /**
     * @return the record, or empty if the file does not exist
     */
    public static Optional<SandyStatusRecord> read(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return Optional.empty();
        }
        byte[] content;
        try (InputStream inputStream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            content = inputStream.readNBytes(MAX_BYTES + 1);
        }
        if (content.length > MAX_BYTES) {
            throw new IOException("The status record of sandy " + path.toAbsolutePath() + " has more than " +
                    MAX_BYTES + " bytes");
        }
        return Optional.of(parse(new String(content, StandardCharsets.UTF_8)));
    }

    static SandyStatusRecord parse(String content) {
        return new SandyStatusRecord(content.lines()
                .map(String::trim)
                .filter(line -> !line.isEmpty())
                .toList());
    }

    // sandy wrote the process ID of the program.
    boolean hasProgramStarted() {
        return lines.stream().anyMatch(line -> line.startsWith(PID_PREFIX));
    }

    // sandy itself failed or refused.
    boolean hasSandyFailed() {
        return lines.contains(FAILED);
    }

    @Override
    public String toString() {
        return lines.isEmpty() ? "empty" : String.join(", ", lines);
    }
}
