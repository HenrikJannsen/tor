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
import java.util.List;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The pluggable transports which Tor starts in its sandbox.
 *
 * @param transportNames the transports of the bridges, for example obfs4 or snowflake
 * @param programPaths   the absolute paths of their programs, which the sandbox lets Tor start
 */
public record SandboxedTransports(Set<String> transportNames, List<Path> programPaths) {
    public static final SandboxedTransports NONE = new SandboxedTransports(Set.of(), List.of());

    public SandboxedTransports {
        transportNames = Set.copyOf(transportNames);
        programPaths = List.copyOf(programPaths);
        checkArgument(programPaths.stream().allMatch(Path::isAbsolute), "The program paths must be absolute");
        checkArgument(transportNames.isEmpty() == programPaths.isEmpty(),
                "Transports need programs, and programs need transports");
    }

    public boolean isEmpty() {
        return programPaths.isEmpty();
    }
}
