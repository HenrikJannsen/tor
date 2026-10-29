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

package bisq.network.tor.common.platform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The OS selects the Tor binary and its path, so the os.name of each system must match exactly one OS.
 */
class OSTest {
    @Test
    void linuxIsOnlyLinux() {
        assertThat(OS.isLinux("Linux")).isTrue();
        assertThat(OS.isMacOs("Linux")).isFalse();
        assertThat(OS.isWindows("Linux")).isFalse();
    }

    @Test
    void macOsIsOnlyMacOs() {
        assertThat(OS.isMacOs("Mac OS X")).isTrue();
        assertThat(OS.isLinux("Mac OS X")).isFalse();
        assertThat(OS.isWindows("Mac OS X")).isFalse();
    }

    // "darwin" contains "win", but a JVM which reports Darwin must not get the binary path of Windows
    @Test
    void darwinIsMacOsAndNotWindows() {
        assertThat(OS.isMacOs("Darwin")).isTrue();
        assertThat(OS.isWindows("Darwin")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"Windows 10", "Windows 11", "Windows Server 2025"})
    void windowsIsOnlyWindows(String osName) {
        assertThat(OS.isWindows(osName)).isTrue();
        assertThat(OS.isMacOs(osName)).isFalse();
        assertThat(OS.isLinux(osName)).isFalse();
    }
}
