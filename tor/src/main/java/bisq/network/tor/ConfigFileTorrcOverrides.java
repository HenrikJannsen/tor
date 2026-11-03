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

package bisq.network.tor;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.Set;

/**
 * The torrc overrides which the application read from a configuration file that it also writes itself, unlike its
 * command line and its code. Whoever can change such a file could otherwise make the next start of Tor run code with the
 * rights of the user, also with the sandbox off, which such a file can turn off as well. So Tor does not start if one of
 * these overrides makes it start a program or load a library ({@link TorrcClientConfigFactory#codeRunningKeys}).
 */
@Getter
@ToString
@EqualsAndHashCode
public final class ConfigFileTorrcOverrides {
    public static final ConfigFileTorrcOverrides NONE = new ConfigFileTorrcOverrides(Set.of(), "");

    // The keys of the torrc overrides which come from the configuration file
    private final Set<String> keys;
    // How the user gives such an override instead, for the message of the refusal
    private final String hint;

    public ConfigFileTorrcOverrides(Set<String> keys, String hint) {
        this.keys = Set.copyOf(keys);
        this.hint = hint;
    }
}
