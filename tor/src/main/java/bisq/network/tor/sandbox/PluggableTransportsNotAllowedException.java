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

import lombok.Getter;

import java.util.List;

/**
 * Bisq did not start Tor because the bridges use pluggable transports, which the configuration of the sandbox does not
 * let Tor start. The sandbox itself could run: the application can tell the user how to allow the transports in its
 * own terms, or let the user choose other bridges.
 */
@Getter
public class PluggableTransportsNotAllowedException extends SandboxUnavailableException {
    // The transports of the bridges, sorted, for example obfs4
    private final List<String> transportNames;

    public PluggableTransportsNotAllowedException(String reason, String optOutHint, List<String> transportNames) {
        super(reason, optOutHint);
        this.transportNames = List.copyOf(transportNames);
    }
}
