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

package bisq.network.tor.process;

import bisq.network.tor.common.platform.OS;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class BundledTorLibrariesTest {
    private static final Path BINARY_DIR = Paths.get("/home/user/.local/share/Bisq/tor/bin");

    @Test
    void onLinuxTheLoaderSearchesTheBinaryDirectoryOnly() {
        assumeTrue(OS.isLinux());
        assertThat(BundledTorLibraries.environment(BINARY_DIR, true))
                .containsExactly(Map.entry("LD_LIBRARY_PATH", BINARY_DIR.toString()));
    }

    @Test
    void theOtherPlatformsNeedNoVariable() {
        assertThat(BundledTorLibraries.environment(BINARY_DIR, false)).isEmpty();
    }

    // The loader would search the parts of the path, also relative to the working directory of Tor.
    @Test
    void aPathWhichTheLoaderWouldSplitFailsTheStart() {
        assumeTrue(OS.isLinux());
        Path withColon = Paths.get("/home/user/a:b/tor/bin");
        Path withSemicolon = Paths.get("/home/user/a;b/tor/bin");

        assertThatThrownBy(() -> BundledTorLibraries.environment(withColon, true))
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining(withColon.toString());
        assertThatThrownBy(() -> BundledTorLibraries.environment(withSemicolon, true))
                .isInstanceOf(TorStartupFailedException.class);
        // Only Linux uses the variable.
        assertThat(BundledTorLibraries.environment(withColon, false)).isEmpty();
    }

    @Test
    void noLoaderVariableOfBisqReachesTor() {
        assumeTrue(OS.isLinux());
        Map<String, String> environment = new HashMap<>(Map.of("LD_PRELOAD", "/tmp/inject.so",
                "LD_AUDIT", "/tmp/audit.so",
                "LD_LIBRARY_PATH", "/opt/other/lib",
                "HOME", "/home/user"));

        BundledTorLibraries.applyToEnvironment(environment, BINARY_DIR, true);

        assertThat(environment).containsOnly(Map.entry("LD_LIBRARY_PATH", BINARY_DIR.toString()),
                Map.entry("HOME", "/home/user"));
    }

    @Test
    void onTheOtherPlatformsBisqsLoaderVariablesAreRemovedToo() {
        Map<String, String> environment = new HashMap<>(Map.of("LD_PRELOAD", "/tmp/inject.so", "HOME", "/home/user"));

        BundledTorLibraries.applyToEnvironment(environment, BINARY_DIR, false);

        assertThat(environment).containsOnly(Map.entry("HOME", "/home/user"));
    }
}
