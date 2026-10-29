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

import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.sandbox.Sandy;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TorServiceSandboxedTorCommandTest {
    private static final Path TOR = Paths.get("/usr/bin/tor");
    private static final Path TORRC = Paths.get("/opt/app/tor/torrc");

    // sandy ends Tor with Bisq there, and in the PID namespace of contained Tor cannot see the process of Bisq.
    @Test
    void torGetsNoOwnerProcessInALevelThatEndsWithItsParent() {
        var level = new Sandy.Level("contained", Set.of(Sandy.ENDS_WITH_PARENT, Sandy.SIGNALS_ISOLATED));

        assertThat(TorService.sandboxedTorCommand(TOR, TORRC, level, "4711"))
                .containsExactly(TOR.toAbsolutePath().toString(),
                        "-f", TORRC.toAbsolutePath().toString(),
                        "--defaults-torrc", TORRC.toAbsolutePath().toString());
    }

    // As in host-network-signals: sandy does not end Tor with Bisq, so the owner check of Tor does.
    @Test
    void torGetsBisqAsItsOwnerInALevelThatDoesNotEndWithItsParent() {
        var level = new Sandy.Level("host-network-signals", Set.of("filesystem-confined"));

        assertThat(TorService.sandboxedTorCommand(TOR, TORRC, level, "4711"))
                .endsWith(EmbeddedTorProcess.ARG_OWNER_PID, "4711");
    }
}
