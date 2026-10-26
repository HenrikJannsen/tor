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

import bisq.network.tor.bridges.BridgeTorrcEntries;
import bisq.network.tor.common.torrc.BaseTorrcGenerator;
import bisq.network.tor.common.torrc.ClientTorrcGenerator;
import bisq.network.tor.common.torrc.TestNetworkTorrcGenerator;
import bisq.network.tor.common.torrc.TorrcConfigGenerator;
import bisq.network.tor.common.torrc.TorrcSyntax;
import bisq.network.tor.controller.PasswordDigest;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static bisq.network.tor.common.torrc.Torrc.Keys.CONTROL_PORT;
import static bisq.network.tor.common.torrc.Torrc.Keys.CONTROL_PORT_WRITE_TO_FILE;
import static bisq.network.tor.common.torrc.Torrc.Keys.CONFLUX_ENABLED;
import static bisq.network.tor.common.torrc.Torrc.Keys.DATA_DIRECTORY;
import static bisq.network.tor.common.torrc.Torrc.Keys.DISABLE_NETWORK;
import static bisq.network.tor.common.torrc.Torrc.Keys.HASHED_CONTROL_PASSWORD;
import static bisq.network.tor.common.torrc.Torrc.Keys.SOCKS_PORT;
import static com.google.common.base.Preconditions.checkArgument;

@Slf4j
@Builder
public class TorrcClientConfigFactory {
    // TorService reads the control port from the file which Tor writes, authenticates with the password of this start
    // and checks its hash, and gives each stream of the SOCKS listener its own circuit. An override of these keys
    // would break the start of Tor or this isolation.
    private static final String AVOID_DISK_WRITES = "AvoidDiskWrites";
    private static final Set<String> KEYS_OWNED_BY_BISQ = Stream.of(CONTROL_PORT, CONTROL_PORT_WRITE_TO_FILE,
                    SOCKS_PORT, DATA_DIRECTORY, HASHED_CONTROL_PASSWORD, DISABLE_NETWORK, CONFLUX_ENABLED)
            .map(key -> key.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());

    // Bisq alone controls the embedded Tor. Bisq sets none of these options; each would let another program control
    // Tor: a control listener on a Unix socket (ControlSocket), an authenticated control connection on an inherited
    // file descriptor (__OwningControllerFD), a second password (__HashedControlSessionPassword), the cookie, which
    // every program that can read its file may use (CookieAuthentication, CookieAuthFile,
    // CookieAuthFileGroupReadable), or control sockets which the group of the user may write
    // (ControlSocketsGroupWritable).
    private static final Set<String> CONTROL_ACCESS_KEYS = Set.of("controlsocket", "controlsocketsgroupwritable",
            "owningcontrollerfd", "hashedcontrolsessionpassword", "cookieauthentication", "cookieauthfile",
            "cookieauthfilegroupreadable");

    private static final Set<String> BRIDGE_KEYS = BridgeTorrcEntries.KEYS.stream()
            .map(key -> key.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());

    private final boolean isTestNetwork;
    private final Path dataDirPath;
    private final PasswordDigest hashedControlPassword;
    // With the bridges of the Bisq configuration, Bisq also sets the torrc keys of the bridges.
    private final boolean usesBridges;

    public TorrcClientConfigFactory(boolean isTestNetwork,
                                    Path dataDirPath,
                                    PasswordDigest hashedControlPassword,
                                    boolean usesBridges) {
        this.isTestNetwork = isTestNetwork;
        this.dataDirPath = dataDirPath;
        this.hashedControlPassword = hashedControlPassword;
        this.usesBridges = usesBridges;
    }

    public Map<String, String> torrcClientConfigMap(Map<String, String> torrcOverrides) {
        Map<String, String> torrcClientConfig = clientTorrcGenerator().generate();
        // Tor writes its state less often, as in Tor Browser and in netlayer. A torrc override can change it.
        torrcClientConfig.put(AVOID_DISK_WRITES, "1");
        torrcOverrides.forEach((key, value) -> {
            // The rules below compare option names. Tor reads "+Key", "/Key" and "Key#x" as a change of the option
            // Key, which they would bypass.
            checkArgument(TorrcSyntax.isOptionName(key), "The key of the torrc override '%s' is not the name of a " +
                    "Tor option. The forms +Key, /Key and Key#comment of a torrc are not supported.", key);
            if (isOwnedByBisq(key)) {
                log.warn("We ignore the torrc override of {}, because Bisq sets it for the embedded Tor", key);
            } else if (isControlAccessKey(key)) {
                log.warn("We ignore the torrc override of {}, because Bisq alone controls the embedded Tor", key);
            } else if (usesBridges && isPrefixOfAny(key, BRIDGE_KEYS)) {
                log.warn("We ignore the torrc override of {}, because Bisq sets the bridges of its configuration", key);
            } else {
                // An override replaces a key of Bisq which it names in any case or as an abbreviation. Otherwise both
                // entries would be written, and Tor would take one of them by the order of the map.
                torrcClientConfig.keySet().removeIf(existingKey -> sets(key, existingKey));
                torrcClientConfig.put(key, value);
            }
        });
        torrcClientConfig.put(DISABLE_NETWORK, "1");
        torrcClientConfig.put(CONFLUX_ENABLED, "0");
        return torrcClientConfig;
    }

    // Tor reads the hidden options __ControlPort and __SocksPort, also abbreviated, as ControlPort and SocksPort. The
    // other keys of Bisq have no hidden form: Tor refuses __DataDirectory, for example, as an unknown option.
    private static boolean isOwnedByBisq(String key) {
        return isPrefixOfAny(key.replaceFirst("^_+", ""), KEYS_OWNED_BY_BISQ);
    }

    // __OwningControllerFD and __HashedControlSessionPassword exist only in the hidden form.
    private static boolean isControlAccessKey(String key) {
        return isPrefixOfAny(key.replaceFirst("^_+", ""), CONTROL_ACCESS_KEYS);
    }

    /**
     * Whether Tor reads the torrc key {@code key} as the option {@code optionName}: in any case, or as the start of
     * the name, which Tor accepts as an abbreviation.
     */
    public static boolean sets(String key, String optionName) {
        return isPrefixOfAny(key, Set.of(optionName.toLowerCase(Locale.ROOT)));
    }

    // Tor ignores the case of option names and accepts the start of an option name as an abbreviation.
    private static boolean isPrefixOfAny(String key, Set<String> lowerCaseKeys) {
        String lowerCaseKey = key.toLowerCase(Locale.ROOT);
        return !lowerCaseKey.isEmpty() && lowerCaseKeys.stream().anyMatch(candidate -> candidate.startsWith(lowerCaseKey));
    }

    private TorrcConfigGenerator clientTorrcGenerator() {
        TorrcConfigGenerator baseTorrcGenerator = baseTorrcGenerator();
        if (isTestNetwork) {
            baseTorrcGenerator = testNetworkTorrcGenerator(baseTorrcGenerator);
        }

        return ClientTorrcGenerator.builder()
                .baseTorrcConfigGenerator(baseTorrcGenerator)
                .build();
    }

    private TorrcConfigGenerator baseTorrcGenerator() {
        return BaseTorrcGenerator.builder()
                .dataDirPath(dataDirPath)
                .hashedControlPassword(hashedControlPassword.getHashedPassword())
                .isTestNetwork(isTestNetwork)
                .build();
    }

    private static TorrcConfigGenerator testNetworkTorrcGenerator(TorrcConfigGenerator baseTorrcGenerator) {
        return TestNetworkTorrcGenerator.builder()
                .baseTorrcConfigGenerator(baseTorrcGenerator)
                .build();
    }
}
