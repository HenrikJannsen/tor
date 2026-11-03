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

import bisq.network.tor.common.torrc.DirectoryAuthority;
import com.typesafe.config.ConfigList;
import com.typesafe.config.ConfigOrigin;
import com.typesafe.config.ConfigValue;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@Getter
@ToString
@EqualsAndHashCode
public class TorTransportConfig {
    // The path of the torrc overrides in the configuration of Bisq 2
    public static final String BISQ2_TORRC_OVERRIDES_PATH = "application.network.configByTransportType.tor.torrcOverrides";

    public static TorTransportConfig from(Path dataDirPath, com.typesafe.config.Config config) {
        com.typesafe.config.Config torrcOverrides = config.getConfig("torrcOverrides");
        return new TorTransportConfig(
                dataDirPath,
                (int) TimeUnit.SECONDS.toMillis(config.getInt("bootstrapTimeout")),
                (int) TimeUnit.SECONDS.toMillis(config.getInt("hsUploadTimeout")),
                config.getBoolean("testNetwork"),
                parseDirectoryAuthorities(config.getList("directoryAuthorities")),
                parseTorrcOverrideConfig(torrcOverrides),
                config.getBoolean("useExternalTor"),
                parseBridgeConfig(config),
                TorSandboxConfig.from(config),
                parseConfigFileTorrcOverrides(torrcOverrides)
        );
    }

    /**
     * Bisq 2 reads its configuration from its program arguments, its JVM options, the file bisq.conf in its data
     * directory, which it also writes itself, and its resources. An override which it read from a file that is not one
     * of its resources comes from bisq.conf or from a file which bisq.conf includes. Where keys of several sources are
     * merged, the origin is the one of the value which Bisq 2 uses.
     */
    private static ConfigFileTorrcOverrides parseConfigFileTorrcOverrides(com.typesafe.config.Config torrcOverrides) {
        Set<String> keys = torrcOverrides.entrySet().stream()
                .filter(entry -> isReadFromFile(entry.getValue().origin()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        return new ConfigFileTorrcOverrides(keys, "Bisq accepts them only as program arguments or JVM options, for " +
                "example -D" + BISQ2_TORRC_OVERRIDES_PATH + ".<name>=<value>: remove them from bisq.conf.");
    }

    // A resource has a file name too if it is read from a directory instead of a jar, for example in a test.
    private static boolean isReadFromFile(ConfigOrigin origin) {
        return origin.filename() != null && origin.resource() == null;
    }

    // The bridges are optional, so that a configuration without them stays valid.
    private static BridgeConfig parseBridgeConfig(com.typesafe.config.Config config) {
        String builtInBridges = config.hasPath("builtInBridges") ? config.getString("builtInBridges").trim() : "";
        List<String> bridges = config.hasPath("bridges") ? config.getStringList("bridges") : List.of();
        if (!builtInBridges.isEmpty() && !bridges.isEmpty()) {
            throw new IllegalArgumentException("Set either builtInBridges or bridges, not both");
        }
        if (!builtInBridges.isEmpty()) {
            return BridgeConfig.builtIn(builtInBridges);
        }
        return bridges.isEmpty() ? BridgeConfig.NONE : BridgeConfig.custom(bridges);
    }

    private static Set<DirectoryAuthority> parseDirectoryAuthorities(ConfigList directoryAuthoritiesConfig) {
        Set<DirectoryAuthority> allDirectoryAuthorities = new HashSet<>();
        directoryAuthoritiesConfig.forEach(authConfig -> {
            DirectoryAuthority directoryAuthority = DirectoryAuthority.builder()
                    .nickname(getStringFromConfigValue(authConfig, "nickname"))
                    .orPort(Integer.parseInt(getStringFromConfigValue(authConfig, "orPort")))
                    .v3Ident(getStringFromConfigValue(authConfig, "v3Ident"))
                    .dirPort(Integer.parseInt(getStringFromConfigValue(authConfig, "dirPort")))
                    .relayFingerprint(getStringFromConfigValue(authConfig, "relayFingerprint"))
                    .build();

            allDirectoryAuthorities.add(directoryAuthority);
        });
        return allDirectoryAuthorities;
    }

    private static Map<String, String> parseTorrcOverrideConfig(com.typesafe.config.Config torrcOverrides) {
        Map<String, String> torrcOverrideConfigMap = new HashMap<>();
        torrcOverrides.entrySet()
                .forEach(entry -> torrcOverrideConfigMap.put(
                        entry.getKey(), (String) entry.getValue().unwrapped()
                ));
        return torrcOverrideConfigMap;
    }

    private static String getStringFromConfigValue(ConfigValue configValue, String key) {
        return (String) configValue
                .atKey(key)
                .getObject(key)
                .get(key)
                .unwrapped();
    }

    private final Path dataDirPath;
    private final int bootstrapTimeout; // in ms
    private final int hsUploadTimeout; // in ms
    private final boolean isTestNetwork;
    private final Set<DirectoryAuthority> directoryAuthorities;
    private final Map<String, String> torrcOverrides;
    private final boolean useExternalTor;
    // Only for the Tor which Bisq starts
    private final BridgeConfig bridgeConfig;
    // Only for the Tor which Bisq starts
    private final TorSandboxConfig sandboxConfig;
    // The overrides of torrcOverrides which come from a configuration file of the application
    private final ConfigFileTorrcOverrides configFileTorrcOverrides;

    public TorTransportConfig(Path dataDirPath,
                              int bootstrapTimeout,
                              int hsUploadTimeout,
                              boolean isTestNetwork,
                              Set<DirectoryAuthority> directoryAuthorities,
                              Map<String, String> torrcOverrides,
                              boolean useExternalTor) {
        this(dataDirPath,
                bootstrapTimeout,
                hsUploadTimeout,
                isTestNetwork,
                directoryAuthorities,
                torrcOverrides,
                useExternalTor,
                BridgeConfig.NONE);
    }

    public TorTransportConfig(Path dataDirPath,
                              int bootstrapTimeout,
                              int hsUploadTimeout,
                              boolean isTestNetwork,
                              Set<DirectoryAuthority> directoryAuthorities,
                              Map<String, String> torrcOverrides,
                              boolean useExternalTor,
                              BridgeConfig bridgeConfig) {
        this(dataDirPath,
                bootstrapTimeout,
                hsUploadTimeout,
                isTestNetwork,
                directoryAuthorities,
                torrcOverrides,
                useExternalTor,
                bridgeConfig,
                TorSandboxConfig.DISABLED);
    }

    public TorTransportConfig(Path dataDirPath,
                              int bootstrapTimeout,
                              int hsUploadTimeout,
                              boolean isTestNetwork,
                              Set<DirectoryAuthority> directoryAuthorities,
                              Map<String, String> torrcOverrides,
                              boolean useExternalTor,
                              BridgeConfig bridgeConfig,
                              TorSandboxConfig sandboxConfig) {
        this(dataDirPath,
                bootstrapTimeout,
                hsUploadTimeout,
                isTestNetwork,
                directoryAuthorities,
                torrcOverrides,
                useExternalTor,
                bridgeConfig,
                sandboxConfig,
                ConfigFileTorrcOverrides.NONE);
    }

    public TorTransportConfig(Path dataDirPath,
                              int bootstrapTimeout,
                              int hsUploadTimeout,
                              boolean isTestNetwork,
                              Set<DirectoryAuthority> directoryAuthorities,
                              Map<String, String> torrcOverrides,
                              boolean useExternalTor,
                              BridgeConfig bridgeConfig,
                              TorSandboxConfig sandboxConfig,
                              ConfigFileTorrcOverrides configFileTorrcOverrides) {
        this.dataDirPath = dataDirPath;
        this.bootstrapTimeout = bootstrapTimeout;
        this.hsUploadTimeout = hsUploadTimeout;
        this.isTestNetwork = isTestNetwork;
        this.directoryAuthorities = directoryAuthorities;
        this.torrcOverrides = torrcOverrides;
        this.useExternalTor = useExternalTor;
        this.bridgeConfig = bridgeConfig;
        this.sandboxConfig = sandboxConfig;
        this.configFileTorrcOverrides = configFileTorrcOverrides;
    }
}