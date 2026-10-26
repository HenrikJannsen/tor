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

import com.typesafe.config.Config;
import com.typesafe.config.ConfigException;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigParseOptions;
import com.typesafe.config.ConfigSyntax;
import com.typesafe.config.ConfigUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The pluggable transports and the built-in bridges of the Tor Browser version of the bundled Tor, from the file
 * pt_config.json of the Tor expert bundle. Tor Browser builds its torrc from the same file.
 */
public final class PluggableTransportConfig {
    private static final String CLIENT_TRANSPORT_PLUGIN = "ClientTransportPlugin";
    private static final String EXEC = "exec";
    // Tor Browser replaces it with the directory of the programs
    private static final String PT_PATH_VARIABLE = "${pt_path}";

    private final List<TransportPlugin> transportPlugins;
    private final Map<String, List<String>> builtInBridgesByName;

    private PluggableTransportConfig(List<TransportPlugin> transportPlugins,
                                     Map<String, List<String>> builtInBridgesByName) {
        this.transportPlugins = List.copyOf(transportPlugins);
        // Keeps the order of the names
        this.builtInBridgesByName = Collections.unmodifiableMap(new LinkedHashMap<>(builtInBridgesByName));
    }

    public static PluggableTransportConfig read(Path ptConfigPath) {
        try {
            return parse(Files.readString(ptConfigPath, StandardCharsets.UTF_8));
        } catch (IOException e) {
            // Without the cause, so that the message which names the file is the root cause which Bisq 2 shows
            throw new IllegalStateException("Could not read the configuration of the pluggable transports " +
                    ptConfigPath + ": " + e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid configuration of the pluggable transports " + ptConfigPath +
                    ": " + e.getMessage());
        }
    }

    /**
     * @throws IllegalArgumentException if the content is not a pt_config.json which Bisq understands
     */
    static PluggableTransportConfig parse(String json) {
        try {
            Config config = ConfigFactory.parseString(json, ConfigParseOptions.defaults().setSyntax(ConfigSyntax.JSON));
            Config pluggableTransports = config.getConfig("pluggableTransports");
            List<TransportPlugin> transportPlugins = pluggableTransports.root().keySet().stream()
                    .sorted()
                    .map(name -> parseTransportPlugin(pluggableTransports.getString(ConfigUtil.joinPath(name))))
                    .toList();

            Config bridges = config.getConfig("bridges");
            Map<String, List<String>> builtInBridgesByName = new LinkedHashMap<>();
            bridges.root().keySet().stream()
                    .sorted()
                    .forEach(name -> {
                        List<String> bridgeLines = bridges.getStringList(ConfigUtil.joinPath(name));
                        // A type without bridges counts as unknown: Tor refuses UseBridges 1 without a Bridge entry.
                        if (!bridgeLines.isEmpty()) {
                            builtInBridgesByName.put(name, bridgeLines);
                        }
                    });
            return new PluggableTransportConfig(transportPlugins, builtInBridgesByName);
        } catch (ConfigException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    // For example "ClientTransportPlugin meek_lite,obfs4,webtunnel exec ${pt_path}lyrebird"
    private static TransportPlugin parseTransportPlugin(String line) {
        List<String> tokens = Arrays.asList(line.trim().split("\\s+"));
        if (tokens.size() < 4 ||
                !tokens.get(0).equals(CLIENT_TRANSPORT_PLUGIN) ||
                !tokens.get(2).equals(EXEC) ||
                !tokens.get(3).startsWith(PT_PATH_VARIABLE)) {
            throw new IllegalArgumentException("Unexpected transport plugin line: " + line);
        }
        String programName = tokens.get(3).substring(PT_PATH_VARIABLE.length());
        if (programName.isEmpty() || programName.contains("$") || programName.contains("/") ||
                programName.contains("\\")) {
            throw new IllegalArgumentException("Unexpected program in the transport plugin line: " + line);
        }
        List<String> transports = Arrays.asList(tokens.get(1).split(","));
        return new TransportPlugin(transports, programName, tokens.subList(4, tokens.size()));
    }

    public List<TransportPlugin> getTransportPlugins() {
        return transportPlugins;
    }

    public Set<String> getBuiltInBridgesNames() {
        return builtInBridgesByName.keySet();
    }

    public Optional<List<String>> findBuiltInBridges(String name) {
        return Optional.ofNullable(builtInBridgesByName.get(name));
    }

    /**
     * A program which provides pluggable transports to Tor.
     *
     * @param transports  the names of the transports, for example obfs4 and webtunnel
     * @param programName the file name of the program in the directory of the pluggable transports, without the
     *                    extension .exe on Windows
     * @param arguments   the arguments which Tor passes to the program
     */
    public record TransportPlugin(List<String> transports, String programName, List<String> arguments) {
        public TransportPlugin {
            transports = List.copyOf(transports);
            arguments = List.copyOf(arguments);
        }
    }
}
