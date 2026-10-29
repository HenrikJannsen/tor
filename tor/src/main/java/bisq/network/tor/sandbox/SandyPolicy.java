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

import java.nio.file.Path;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * A sandy policy as the TOML text of sandy 2.4.1 that Bisq passes on the standard input of sandy
 * ({@code --policy -}), with the working directory of the program, which sandy takes on its command line. The policy
 * and its fallback levels come from a template of the library (see {@link TorSandboxPolicy}); Bisq does not decide
 * how strongly Tor is isolated, sandy does, by the level it selects.
 */
public record SandyPolicy(String toml, Path workingDirPath) {
    /**
     * The program connects to {@code innerPort} and sandy relays each connection to {@code outerPort} outside the
     * sandbox.
     */
    public record ForwardedPort(int innerPort, int outerPort) {
        public ForwardedPort {
            checkPort(innerPort);
            checkPort(outerPort);
        }
    }

    static void checkPort(int port) {
        checkArgument(port > 0 && port <= 65535, "Invalid port: " + port);
    }
}
