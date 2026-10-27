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
 * Stripped copy of bisq.common.platform.OS with the members which the Tor build uses.
 */
public enum OS {
    LINUX,
    MAC_OS,
    WINDOWS,
    ANDROID;

    public static OS getOS() {
        if (isLinux()) {
            return LINUX;
        } else if (isMacOs()) {
            return MAC_OS;
        } else if (isWindows()) {
            return WINDOWS;
        } else if (isAndroid()) {
            return ANDROID;
        }
        throw new IllegalStateException("Running on unsupported OS: " + getOsName());
    }

    public static boolean isLinux() {
        return isLinux(getOsName()) && !isAndroid();
    }

    public static boolean isMacOs() {
        return isMacOs(getOsName());
    }

    public static boolean isWindows() {
        return isWindows(getOsName());
    }

    // osName is the os.name of the JVM, for example "Linux", "Mac OS X" or "Windows 11". Android reports "Linux".
    static boolean isLinux(String osName) {
        return toLowerCase(osName).contains("linux");
    }

    static boolean isMacOs(String osName) {
        String lowerCaseOsName = toLowerCase(osName);
        return lowerCaseOsName.contains("mac") || lowerCaseOsName.contains("darwin");
    }

    static boolean isWindows(String osName) {
        // Not contains("win"): "darwin" contains it too
        return toLowerCase(osName).startsWith("windows");
    }

    private static boolean isAndroid() {
        try {
            Class.forName("android.os.Build");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static String getOsName() {
        return System.getProperty("os.name");
    }

    private static String toLowerCase(String osName) {
        return osName.toLowerCase(Locale.US);
    }
}
