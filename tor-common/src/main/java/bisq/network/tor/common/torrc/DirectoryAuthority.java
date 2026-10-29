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

package bisq.network.tor.common.torrc;

import lombok.Builder;
import lombok.Getter;

import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkArgument;

@Builder
@Getter
public class DirectoryAuthority {
    // A nickname of Tor: up to 19 letters and digits
    private static final Pattern NICKNAME = Pattern.compile("[A-Za-z0-9]{1,19}");
    // The hex digits of a SHA-1 fingerprint
    private static final Pattern FINGERPRINT = Pattern.compile("[0-9A-Fa-f]{40}");

    private final String nickname;
    private final int orPort;
    private final String v3Ident;
    private final int dirPort;
    private final String relayFingerprint;

    /**
     * @return the value of the torrc option DirAuthority for this authority
     * @throws IllegalArgumentException if a field is not what Tor reads in a DirAuthority entry. The fields come
     *                                  from the configuration; a line break or white space in one of them would
     *                                  otherwise add an entry to the torrc.
     */
    public String toTorrcValue() {
        checkArgument(nickname != null && NICKNAME.matcher(nickname).matches(),
                "The nickname of a directory authority must be 1 to 19 letters or digits");
        checkArgument(v3Ident != null && FINGERPRINT.matcher(v3Ident).matches(),
                "The v3ident of a directory authority must be 40 hex digits");
        checkArgument(relayFingerprint != null && FINGERPRINT.matcher(relayFingerprint).matches(),
                "The fingerprint of a directory authority must be 40 hex digits");
        checkArgument(isPort(orPort), "The orport of a directory authority must be between 1 and 65535");
        checkArgument(isPort(dirPort), "The dirport of a directory authority must be between 1 and 65535");
        return nickname + " orport=" + orPort + " v3ident=" + v3Ident + " 127.0.0.1:" + dirPort + " " + relayFingerprint;
    }

    private static boolean isPort(int port) {
        return port > 0 && port <= 65535;
    }
}
