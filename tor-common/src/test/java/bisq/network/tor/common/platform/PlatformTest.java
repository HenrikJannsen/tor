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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class PlatformTest {
    // The platform name selects the sandy binary of the platform
    @ParameterizedTest
    @CsvSource({
            "LINUX, X86_64, linux_x86_64",
            "LINUX, ARM_64, linux_arm64",
            "MAC_OS, X86_64, macos_x86_64",
            "MAC_OS, ARM_64, macos_arm64",
            "WINDOWS, X86_64, win_x86_64",
            "WINDOWS, ARM_64, win_arm64",
            "ANDROID, X86_64, android_x86_64",
            "ANDROID, ARM_64, android_arm64"})
    void eachOsAndArchitectureHasItsOwnPlatform(OS os, Architecture architecture, String platformName) {
        assertThat(Platform.of(os, architecture).getPlatformName()).isEqualTo(platformName);
    }
}
