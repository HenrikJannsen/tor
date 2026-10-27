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

import java.util.Locale;

/**
 * Stripped copy of bisq.common.platform.Architecture with the members which the Tor build uses.
 */
public enum Architecture {
    X86_64,
    ARM_64;

    public static Architecture getArchitecture() {
        return fromOsArch(System.getProperty("os.arch"));
    }

    // osArch is the os.arch of the JVM, for example "amd64" or "aarch64"
    static Architecture fromOsArch(String osArch) {
        String architectureName = osArch.toLowerCase(Locale.US);
        boolean is64Bit = architectureName.contains("64") || architectureName.contains("armv8");
        if (is64Bit && (architectureName.contains("x86") || architectureName.contains("amd"))) {
            return X86_64;
        } else if (is64Bit && (architectureName.contains("aarch") || architectureName.contains("arm"))) {
            return ARM_64;
        }
        throw new IllegalStateException("Running on unsupported Architecture: " + architectureName);
    }
}
