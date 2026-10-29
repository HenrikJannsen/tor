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

import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BridgeConfigTest {
    private static final String TRANSPORT_CONFIG = """
            bootstrapTimeout = 240
            hsUploadTimeout = 120
            testNetwork = false
            directoryAuthorities = []
            torrcOverrides {}
            useExternalTor = false
            """;

    @Test
    void aConfigurationWithoutBridgesUsesNone() {
        TorTransportConfig config = TorTransportConfig.from(Path.of("tor"), ConfigFactory.parseString(TRANSPORT_CONFIG));

        assertThat(config.getBridgeConfig()).isEqualTo(BridgeConfig.NONE);
        assertThat(config.getBridgeConfig().isUsed()).isFalse();
    }

    @Test
    void theConfigurationNamesBuiltInBridgesOrBridgeLines() {
        TorTransportConfig builtIn = TorTransportConfig.from(Path.of("tor"),
                ConfigFactory.parseString(TRANSPORT_CONFIG + "builtInBridges = snowflake\nbridges = []"));
        TorTransportConfig custom = TorTransportConfig.from(Path.of("tor"),
                ConfigFactory.parseString(TRANSPORT_CONFIG + "bridges = [\"obfs4 192.0.2.1:443 ABC cert=x\"]"));

        assertThat(builtIn.getBridgeConfig()).isEqualTo(BridgeConfig.builtIn("snowflake"));
        assertThat(custom.getBridgeConfig().getCustomBridgeLines()).containsExactly("obfs4 192.0.2.1:443 ABC cert=x");
        assertThatThrownBy(() -> TorTransportConfig.from(Path.of("tor"), ConfigFactory.parseString(TRANSPORT_CONFIG +
                "builtInBridges = obfs4\nbridges = [\"192.0.2.1:443\"]")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("either");
    }

    @Test
    void aBridgeLineCanStartWithTheKeyOfTheTorrc() {
        BridgeConfig config = BridgeConfig.custom(List.of(" Bridge obfs4 192.0.2.1:443 ABC", "bridge 192.0.2.2:9001"));

        assertThat(config.getCustomBridgeLines()).containsExactly("obfs4 192.0.2.1:443 ABC", "192.0.2.2:9001");
    }

    @Test
    void aBridgeLineIsOneLine() {
        assertThatThrownBy(() -> BridgeConfig.custom(List.of("Bridge\nUseBridges 0")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BridgeConfig.custom(List.of("  ")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BridgeConfig.custom(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aBridgeLineWhichTorWouldCutOrJoinIsRefused() {
        // Tor ends the value at a "#" and continues the entry on the next line after a backslash (checked with
        // tor 0.4.9.14 --verify-config).
        assertThatThrownBy(() -> BridgeConfig.custom(List.of("obfs4 192.0.2.1:443 ABC cert=abc#iat-mode=0")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("#")
                .hasMessageNotContaining("192.0.2.1");
        assertThatThrownBy(() -> BridgeConfig.custom(List.of("obfs4 192.0.2.1:443 ABC \\")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("backslash");
        assertThatThrownBy(() -> BridgeConfig.custom(List.of("obfs4 192.0.2.1:443\0ABC")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("control character");
    }

    @Test
    void theBridgeLinesAreNotPrinted() {
        // A bridge which the user got privately would be blocked once it is known.
        assertThat(BridgeConfig.custom(List.of("obfs4 192.0.2.1:443 ABC cert=secret")).toString())
                .doesNotContain("192.0.2.1", "secret");
    }
}
