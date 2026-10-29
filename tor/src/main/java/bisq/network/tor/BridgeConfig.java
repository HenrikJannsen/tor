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

import bisq.network.tor.common.torrc.TorrcSyntax;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The bridges of the Tor which Bisq starts. A bridge is a Tor relay which is not listed publicly. With a pluggable
 * transport such as obfs4, the connection to the bridge does not look like a Tor connection, so a network which blocks
 * Tor can let it through. Bisq either uses no bridges, the built-in bridges of the Tor Browser version of the bundled
 * Tor, or the bridge lines which the user got, for example from https://bridges.torproject.org.
 * <p>
 * An external Tor uses the bridges of its own configuration.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class BridgeConfig {
    public static final BridgeConfig NONE = new BridgeConfig(Optional.empty(), List.of());
    private static final String BRIDGE_KEY = "Bridge";

    // The name of a set of built-in bridges in pt_config.json of the Tor expert bundle, for example "obfs4"
    private final Optional<String> builtInBridges;
    // Lines in the format of the torrc option Bridge, without the word Bridge
    @ToString.Exclude
    private final List<String> customBridgeLines;

    private BridgeConfig(Optional<String> builtInBridges, List<String> customBridgeLines) {
        this.builtInBridges = builtInBridges;
        this.customBridgeLines = List.copyOf(customBridgeLines);
    }

    public static BridgeConfig builtIn(String name) {
        checkArgument(!name.isBlank(), "The name of the built-in bridges is empty");
        return new BridgeConfig(Optional.of(name.trim()), List.of());
    }

    /**
     * @param bridgeLines lines in the format of the torrc option Bridge, for example
     *                    {@code obfs4 192.0.2.1:443 <fingerprint> cert=<cert> iat-mode=0}. A line can start with the
     *                    word Bridge, as in a torrc.
     */
    public static BridgeConfig custom(List<String> bridgeLines) {
        checkArgument(!bridgeLines.isEmpty(), "No bridge lines");
        // Tor reads a bridge line as the value of the torrc option Bridge. A line which Tor would cut at a "#" or join
        // with the next entry is refused, because the user relies on the bridges. The message does not name the line.
        bridgeLines.forEach(line -> TorrcSyntax.findValueProblem(line).ifPresent(problem -> {
            throw new IllegalArgumentException("A bridge line " + problem);
        }));
        List<String> normalizedLines = bridgeLines.stream().map(BridgeConfig::normalize).collect(Collectors.toList());
        normalizedLines.forEach(line -> checkArgument(!line.isEmpty(), "A bridge line is empty"));
        return new BridgeConfig(Optional.empty(), normalizedLines);
    }

    private static String normalize(String bridgeLine) {
        String trimmedLine = bridgeLine.trim();
        String[] tokens = trimmedLine.split("\\s+", 2);
        return tokens.length == 2 && tokens[0].equalsIgnoreCase(BRIDGE_KEY) ? tokens[1] : trimmedLine;
    }

    public boolean isUsed() {
        return builtInBridges.isPresent() || !customBridgeLines.isEmpty();
    }
}
