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

import bisq.network.tor.controller.PasswordDigest;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorrcClientConfigFactoryTest {
    private static final Path DATA_DIR = Paths.get("").toAbsolutePath().resolve("tor");
    private final PasswordDigest passwordDigest = PasswordDigest.generateDigest();
    private final TorrcClientConfigFactory factory = TorrcClientConfigFactory.builder()
            .isTestNetwork(false)
            .dataDirPath(DATA_DIR)
            .hashedControlPassword(passwordDigest)
            .build();

    @Test
    void bisqOwnsTheListenersTheControlPasswordAndTheDataDirectory() {
        // Tor ignores the case of option names and accepts abbreviations of them.
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put("SocksPort", "127.0.0.1:9050 NoIsolateSOCKSAuth");
        overrides.put("controlport", "9051");
        overrides.put("DATADIRECTORY", "/home/user");
        overrides.put("HashedControlPass", "16:00");
        overrides.put("ControlPortWriteTo", "/tmp/control");
        overrides.put("DisableNetwork", "0");
        overrides.put("ConnectionPadding", "1");

        Map<String, String> torrc = factory.torrcClientConfigMap(overrides);

        assertThat(torrc)
                .containsEntry("ControlPort", "127.0.0.1:auto")
                .containsEntry("SocksPort", "auto")
                .containsEntry("DataDirectory", DATA_DIR.toString())
                .containsEntry("HashedControlPassword", passwordDigest.getHashedPassword())
                .containsEntry("DisableNetwork", "1")
                .containsEntry("ConnectionPadding", "1")
                .doesNotContainKeys("controlport", "DATADIRECTORY", "HashedControlPass", "ControlPortWriteTo");
    }

    @Test
    void confluxIsDisabledAndCannotBeEnabledByAnOverride() {
        assertThat(factory.torrcClientConfigMap(Map.of())).containsEntry("ConfluxEnabled", "0");
        assertThat(factory.torrcClientConfigMap(Map.of("confluxenab", "1")))
                .containsEntry("ConfluxEnabled", "0")
                .doesNotContainKey("confluxenab");
    }

    // An override of __SocksPort with NoIsolateSOCKSAuth would add a SOCKS listener without stream isolation.
    @Test
    void theHiddenFormsOfTheListenersBelongToBisqToo() {
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put("__SocksPort", "127.0.0.1:19999 NoIsolateSOCKSAuth");
        overrides.put("__controlport", "127.0.0.1:19998");
        overrides.put("__Sock", "127.0.0.1:19997");
        overrides.put("__Control", "127.0.0.1:19996");

        Map<String, String> torrc = factory.torrcClientConfigMap(overrides);

        assertThat(torrc)
                .containsEntry("ControlPort", "127.0.0.1:auto")
                .containsEntry("SocksPort", "auto")
                .doesNotContainKeys("__SocksPort", "__controlport", "__Sock", "__Control");
    }

    // Each of these options would let another program control the embedded Tor besides Bisq.
    @Test
    void noOverrideAddsAWayToControlTor() {
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put("ControlSocket", "/tmp/tor-control");
        overrides.put("controlsocketsgroupwritable", "1");
        overrides.put("__OwningControllerFD", "3");
        overrides.put("__HashedControlSessionPassword", "16:00");
        overrides.put("__HashedControlSess", "16:01");
        overrides.put("CookieAuthentication", "1");
        overrides.put("CookieAuth", "1");
        overrides.put("CookieAuthFile", "/tmp/cookie");
        overrides.put("CookieAuthFileGroupReadable", "1");

        Map<String, String> torrc = factory.torrcClientConfigMap(overrides);

        assertThat(torrc)
                .containsEntry("ControlPort", "127.0.0.1:auto")
                .containsEntry("HashedControlPassword", passwordDigest.getHashedPassword())
                .doesNotContainKeys(overrides.keySet().toArray(String[]::new));
    }

    @Test
    void anOverrideWhoseKeyIsNotAnOptionNameStopsTheStart() {
        // Tor reads "+ControlPort" as a second control port, "/ControlPort" as the removal of the control port and
        // "ControlPort#x" as ControlPort without value, which resets it. None is a prefix of a key of Bisq.
        for (String key : List.of("+ControlPort", "/ControlPort", "ControlPort#x", "+SocksPort", "%include")) {
            assertThatThrownBy(() -> factory.torrcClientConfigMap(Map.of(key, "127.0.0.1:19051")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(key);
        }
    }

    @Test
    void torAvoidsDiskWritesUnlessTheUserChangesIt() {
        assertThat(factory.torrcClientConfigMap(Map.of())).containsEntry("AvoidDiskWrites", "1");
        assertThat(factory.torrcClientConfigMap(Map.of("avoiddiskwrites", "0")))
                .containsEntry("avoiddiskwrites", "0")
                .doesNotContainKey("AvoidDiskWrites");
    }

    @Test
    void anOverrideReplacesAKeyOfBisqInAnyCase() {
        Map<String, String> torrc = factory.torrcClientConfigMap(Map.of("log", "info stdout"));

        assertThat(torrc)
                .containsEntry("log", "info stdout")
                .doesNotContainKey("Log");
    }

    // Tor accepts the start of an option name. Both entries would be written, and Tor would take one by map order.
    @Test
    void anAbbreviatedOverrideReplacesAKeyOfBisq() {
        Map<String, String> torrc = factory.torrcClientConfigMap(Map.of("AvoidDiskWrite", "0", "lo", "info stdout"));

        assertThat(torrc)
                .containsEntry("AvoidDiskWrite", "0")
                .containsEntry("lo", "info stdout")
                .doesNotContainKeys("AvoidDiskWrites", "Log");
    }

    @Test
    void optionsWhichOnlyStartLikeAKeyOfBisqAreKept() {
        Map<String, String> torrc = factory.torrcClientConfigMap(Map.of("ControlPortFileGroupReadable", "1",
                "SocksPolicy", "accept 127.0.0.1"));

        assertThat(torrc)
                .containsEntry("ControlPortFileGroupReadable", "1")
                .containsEntry("SocksPolicy", "accept 127.0.0.1");
        assertThat(factory.torrcClientConfigMap(Map.of("LogTimeGranularity", "1000")))
                .containsEntry("Log", "notice file " + DATA_DIR.resolve("debug.log"))
                .containsEntry("LogTimeGranularity", "1000");
    }
}
