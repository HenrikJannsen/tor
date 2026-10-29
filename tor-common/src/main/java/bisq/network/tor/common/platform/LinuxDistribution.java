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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Stripped copy of bisq.common.platform.LinuxDistribution with the methods which the Tor build uses. Unlike the
 * original, it tells the Whonix-Gateway apart, on which Bisq does not run.
 */
public class LinuxDistribution {
    private LinuxDistribution() {
    }

    /**
     * @return whether this is a Whonix-Workstation or a Whonix-Gateway: both have the markers of whonix-base-files
     */
    public static boolean isWhonix() {
        return OS.isLinux() && isWhonix(Paths.get("/"));
    }

    /**
     * @return whether this is a Whonix-Gateway, which runs the Tor of the Whonix-Workstations behind it. Its package
     * anon-gw-base-files has the marker; a Workstation has /usr/share/anon-ws-base-files/workstation instead.
     */
    public static boolean isWhonixGateway() {
        return OS.isLinux() && isWhonixGateway(Paths.get("/"));
    }

    // The markers below the root of the file system, so that a test needs no Whonix
    static boolean isWhonix(Path fileSystemRoot) {
        return Files.isRegularFile(fileSystemRoot.resolve("usr/share/whonix/marker")) &&
                Files.isRegularFile(fileSystemRoot.resolve("usr/share/anon-dist/marker"));
    }

    static boolean isWhonixGateway(Path fileSystemRoot) {
        return isWhonix(fileSystemRoot) &&
                Files.isRegularFile(fileSystemRoot.resolve("usr/share/anon-gw-base-files/gateway"));
    }
}
