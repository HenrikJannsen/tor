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

package bisq.network.tor.bridges;

import bisq.network.tor.BridgeConfig;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The torrc entries which let the embedded Tor connect only through the configured bridges: {@code UseBridges 1}, one
 * {@code Bridge} entry per bridge, and one {@code ClientTransportPlugin} entry per program of the pluggable transports
 * which the bridges use.
 */
public final class BridgeTorrcEntries {
    public static final String USE_BRIDGES = "UseBridges";
    public static final String BRIDGE = "Bridge";
    public static final String CLIENT_TRANSPORT_PLUGIN = "ClientTransportPlugin";
    // The torrc keys of the bridges. Tor ignores the case of option names.
    public static final Set<String> KEYS = Set.of(USE_BRIDGES, BRIDGE, CLIENT_TRANSPORT_PLUGIN);

    // Tor accepts a C identifier as the name of a transport.
    private static final Pattern TRANSPORT_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private BridgeTorrcEntries() {
    }

    /**
     * @param findProgram returns the path of a program of a pluggable transport as Tor has to start it, or empty if
     *                    the program is missing
     * @throws BridgesUnavailableException if a bridge cannot be used. Tor must not start without the bridges, because
     *                                     the user relies on them to get around a block or to hide the use of Tor.
     */
    public static List<Map.Entry<String, String>> create(BridgeConfig bridgeConfig,
                                                         PluggableTransportConfig pluggableTransportConfig,
                                                         Function<String, Optional<String>> findProgram) {
        List<String> bridgeLines = getBridgeLines(bridgeConfig, pluggableTransportConfig);
        Set<String> transports = new LinkedHashSet<>();
        bridgeLines.forEach(line -> findTransport(line).ifPresent(transports::add));

        List<Map.Entry<String, String>> entries = new ArrayList<>();
        entries.add(Map.entry(USE_BRIDGES, "1"));
        bridgeLines.forEach(line -> entries.add(Map.entry(BRIDGE, line)));

        Set<String> transportsWithProgram = new HashSet<>();
        for (PluggableTransportConfig.TransportPlugin plugin : pluggableTransportConfig.getTransportPlugins()) {
            List<String> usedTransports = plugin.transports().stream()
                    .filter(transports::contains)
                    .filter(transport -> !transportsWithProgram.contains(transport))
                    .toList();
            if (usedTransports.isEmpty()) {
                continue;
            }
            String program = findProgram.apply(plugin.programName())
                    .orElseThrow(() -> new BridgesUnavailableException("The program " + plugin.programName() +
                            " of the pluggable transports " + String.join(", ", usedTransports) + " is missing."));
            List<String> pluginTokens = new ArrayList<>();
            pluginTokens.add(String.join(",", usedTransports));
            pluginTokens.add("exec");
            pluginTokens.add(program);
            pluginTokens.addAll(plugin.arguments());
            entries.add(Map.entry(CLIENT_TRANSPORT_PLUGIN, String.join(" ", pluginTokens)));
            transportsWithProgram.addAll(usedTransports);
        }

        Set<String> transportsWithoutProgram = transports.stream()
                .filter(transport -> !transportsWithProgram.contains(transport))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!transportsWithoutProgram.isEmpty()) {
            throw new BridgesUnavailableException("Bisq has no pluggable transport for the bridges of the type " +
                    String.join(", ", transportsWithoutProgram) + ".");
        }
        return entries;
    }

    /**
     * @return the transports and the program of each {@code ClientTransportPlugin} entry of {@code entries}, as
     * {@link #create} writes them: the transports separated by commas, {@code exec}, the program and its arguments
     */
    public static List<ClientTransportPlugin> findClientTransportPlugins(List<Map.Entry<String, String>> entries) {
        return entries.stream()
                .filter(entry -> entry.getKey().equals(CLIENT_TRANSPORT_PLUGIN))
                .map(entry -> {
                    String[] tokens = entry.getValue().split(" ");
                    return new ClientTransportPlugin(List.of(tokens[0].split(",")), tokens[2]);
                })
                .toList();
    }

    /**
     * @param transports the transports which the program provides to Tor
     * @param program    the path of the program as Tor starts it: relative to the directory of the bundle, which is
     *                   the working directory of Tor, or absolute
     */
    public record ClientTransportPlugin(List<String> transports, String program) {
        public ClientTransportPlugin {
            transports = List.copyOf(transports);
        }
    }

    private static List<String> getBridgeLines(BridgeConfig bridgeConfig,
                                               PluggableTransportConfig pluggableTransportConfig) {
        if (bridgeConfig.getBuiltInBridges().isEmpty()) {
            return bridgeConfig.getCustomBridgeLines();
        }
        String name = bridgeConfig.getBuiltInBridges().get();
        return pluggableTransportConfig.findBuiltInBridges(name)
                .orElseThrow(() -> new BridgesUnavailableException("The bundled Tor has no built-in bridges of the " +
                        "type " + name + ". It has built-in bridges of the types " +
                        String.join(", ", pluggableTransportConfig.getBuiltInBridgesNames()) + "."));
    }

    /**
     * A bridge line starts with the name of its transport, or with the address of a bridge without transport, for
     * example {@code obfs4 192.0.2.1:443 <fingerprint> cert=<cert> iat-mode=0} or {@code 192.0.2.1:443}.
     */
    static Optional<String> findTransport(String bridgeLine) {
        String firstToken = bridgeLine.trim().split("\\s+", 2)[0];
        if (firstToken.contains(":")) {
            return Optional.empty();
        }
        if (!TRANSPORT_NAME.matcher(firstToken).matches()) {
            throw new BridgesUnavailableException("A bridge line starts neither with a transport nor with an " +
                    "address: " + firstToken);
        }
        return Optional.of(firstToken);
    }
}
