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

package bisq.gradle.tasks;

import bisq.gradle.common.Platform;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PerPlatformUrlProviderTest {
    private final PerPlatformUrlProvider provider = new PerPlatformUrlProvider() {
        @Override
        public String getUrlPrefix() {
            return "https://example.org/1.0/";
        }

        @Override
        public String getLINUX_X86_64_URL() {
            return "linux-x86_64.tar.gz";
        }

        @Override
        public String getMACOS_X86_64_URL() {
            return "macos-x86_64.tar.gz";
        }

        @Override
        public String getMACOS_ARM_64_URL() {
            return "macos-aarch64.tar.gz";
        }

        @Override
        public String getWIN_X86_64_URL() {
            return "windows-x86_64.tar.gz";
        }
    };

    @Test
    void namesTheBinaryOfEachPlatformWhichHasOne() {
        assertEquals("https://example.org/1.0/linux-x86_64.tar.gz", provider.urlFor(Platform.LINUX_X86_64));
        assertEquals("https://example.org/1.0/macos-x86_64.tar.gz", provider.urlFor(Platform.MACOS_X86_64));
        assertEquals("https://example.org/1.0/macos-aarch64.tar.gz", provider.urlFor(Platform.MACOS_ARM_64));
        assertEquals("https://example.org/1.0/windows-x86_64.tar.gz", provider.urlFor(Platform.WIN_X86_64));
    }

    @Test
    void namesNoBinaryOfAnotherArchitectureForArm64() {
        assertNull(provider.urlFor(Platform.LINUX_ARM_64));
        assertNull(provider.urlFor(Platform.WIN_ARM_64));
    }
}
