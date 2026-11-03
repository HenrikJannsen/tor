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
import com.typesafe.config.ConfigException;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigObject;
import com.typesafe.config.ConfigOrigin;
import com.typesafe.config.ConfigUtil;
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
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Slf4j
@Getter
@ToString
@EqualsAndHashCode
public class TorTransportConfig {
    // The path of the torrc overrides in the configuration of Bisq 2
    public static final String BISQ2_TORRC_OVERRIDES_PATH = "application.network.configByTransportType.tor.torrcOverrides";

    /**
     * Without the sources of the configuration, an override comes from a configuration file only if its value does
     * (see {@link #from(Path, com.typesafe.config.Config, com.typesafe.config.Config, com.typesafe.config.Config)}).
     */
    public static TorTransportConfig from(Path dataDirPath, com.typesafe.config.Config config) {
        return from(dataDirPath, config, ConfigFactory.empty(), ConfigFactory.empty());
    }

    /**
     * @param config      the Tor configuration of Bisq 2, resolved
     * @param configFile  bisq.conf as Bisq 2 parsed it: with what it includes, before its substitutions are resolved
     * @param commandLine the program arguments and JVM options of Bisq 2, which win over bisq.conf
     */
    public static TorTransportConfig from(Path dataDirPath,
                                          com.typesafe.config.Config config,
                                          com.typesafe.config.Config configFile,
                                          com.typesafe.config.Config commandLine) {
        com.typesafe.config.Config torrcOverrides = config.getConfig("torrcOverrides");
        return new TorTransportConfig(
                dataDirPath,
                (int) TimeUnit.SECONDS.toMillis(config.getInt("bootstrapTimeout")),
                (int) TimeUnit.SECONDS.toMillis(config.getInt("hsUploadTimeout")),
                config.getBoolean("testNetwork"),
                parseDirectoryAuthorities(config.getConfigList("directoryAuthorities")),
                parseTorrcOverrideConfig(torrcOverrides),
                config.getBoolean("useExternalTor"),
                parseBridgeConfig(config),
                TorSandboxConfig.from(config),
                parseConfigFileTorrcOverrides(torrcOverrides, configFile, commandLine)
        );
    }

    /**
     * Bisq 2 reads its configuration from its program arguments, its JVM options, the file bisq.conf in its data
     * directory, which it also writes itself, and its resources. An override comes from bisq.conf if bisq.conf assigns
     * it and the command line does not, also if bisq.conf takes the value from elsewhere: with a substitution such as
     * {@code ${x}}, whose resolved value has the origin of x, or with an include. Without bisq.conf, and as a second
     * check, an override comes from a configuration file if Bisq 2 read its value from a file or a URL which is not one
     * of its resources: bisq.conf or what bisq.conf includes.
     */
    private static ConfigFileTorrcOverrides parseConfigFileTorrcOverrides(com.typesafe.config.Config torrcOverrides,
                                                                          com.typesafe.config.Config configFile,
                                                                          com.typesafe.config.Config commandLine) {
        Predicate<String> isAssignedByConfigFile = overridesAssignedBy(configFile.root(),
                ConfigUtil.splitPath(BISQ2_TORRC_OVERRIDES_PATH));
        Set<String> keys = torrcOverrides.entrySet().stream()
                .filter(entry -> isReadFromFileOrUrl(entry.getValue().origin()) ||
                        (isAssignedByConfigFile.test(entry.getKey()) &&
                                !commandLine.hasPath(BISQ2_TORRC_OVERRIDES_PATH + "." + entry.getKey())))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        return new ConfigFileTorrcOverrides(keys, "Bisq accepts them only as program arguments or JVM options, for " +
                "example -D" + BISQ2_TORRC_OVERRIDES_PATH + ".<name>=<value>: remove them from bisq.conf.");
    }

    /**
     * Whether the unresolved file assigns the override of a key, which is a path below the overrides. If the file
     * assigns the overrides or an object above them as a whole, for example with a substitution, it assigns them all.
     */
    private static Predicate<String> overridesAssignedBy(ConfigObject root, List<String> path) {
        ConfigValue value = root;
        try {
            for (String name : path) {
                if (!(value instanceof ConfigObject object)) {
                    return key -> true;
                }
                value = object.get(name);
                if (value == null) {
                    return key -> false;
                }
            }
            if (!(value instanceof ConfigObject overrides)) {
                return key -> true;
            }
            Set<String> names = new HashSet<>(overrides.keySet());
            return key -> names.contains(ConfigUtil.splitPath(key).get(0));
        } catch (ConfigException.NotResolved e) {
            // An object which a substitution extends, for example tor = ${x} { ... }
            return key -> true;
        }
    }

    // bisq.conf can include a file or a URL, for example include url("https://..."), whose values have a URL but no
    // file name. A resource has a file name too if it is read from a directory instead of a jar, for example in a test.
    private static boolean isReadFromFileOrUrl(ConfigOrigin origin) {
        return (origin.filename() != null || origin.url() != null) && origin.resource() == null;
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

    // A port may be a number or a numeric string, as typesafe config converts it.
    private static Set<DirectoryAuthority> parseDirectoryAuthorities(
            List<? extends com.typesafe.config.Config> directoryAuthoritiesConfig) {
        Set<DirectoryAuthority> allDirectoryAuthorities = new HashSet<>();
        directoryAuthoritiesConfig.forEach(authConfig -> {
            DirectoryAuthority directoryAuthority = DirectoryAuthority.builder()
                    .nickname(authConfig.getString("nickname"))
                    .orPort(authConfig.getInt("orPort"))
                    .v3Ident(authConfig.getString("v3Ident"))
                    .dirPort(authConfig.getInt("dirPort"))
                    .relayFingerprint(authConfig.getString("relayFingerprint"))
                    .build();

            allDirectoryAuthorities.add(directoryAuthority);
        });
        return allDirectoryAuthorities;
    }

    /**
     * Tor reads every value as text. A value of bisq.conf without quotes, such as {@code AvoidDiskWrites = 1}, is a
     * number or a boolean in typesafe config, and Bisq 2 turns the values of program arguments and JVM options into
     * numbers and booleans where it can. So a number or a boolean reaches Tor as its text: the text of the
     * configuration file for a number, for example "0123", and "true" or "false" for a boolean. A list is no torrc
     * value and fails with an error which names the path.
     */
    private static Map<String, String> parseTorrcOverrideConfig(com.typesafe.config.Config torrcOverrides) {
        Map<String, String> torrcOverrideConfigMap = new HashMap<>();
        torrcOverrides.entrySet().forEach(entry ->
                torrcOverrideConfigMap.put(entry.getKey(), torrcOverrides.getString(entry.getKey())));
        return torrcOverrideConfigMap;
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