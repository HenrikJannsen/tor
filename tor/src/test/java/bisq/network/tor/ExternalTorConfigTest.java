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

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExternalTorConfigTest {
    @Test
    void theTemplateDoesNotUseAnExternalTor() throws IOException {
        String template;
        try (InputStream inputStream = getClass().getResourceAsStream("/tor/external_tor.config")) {
            template = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        ExternalTorConfig config = ExternalTorConfig.parse(template);

        assertThat(config.getUseExternalTor()).isEmpty();
        assertThat(config.getControlHost()).isEqualTo("127.0.0.1");
        assertThat(config.getControlPort()).isEqualTo(9051);
        assertThat(config.isCookieAuthentication()).isFalse();
    }

    @Test
    void optionNamesAreCaseInsensitiveAndTheLastValueCounts() {
        ExternalTorConfig config = ExternalTorConfig.parse("""
                UseExternalTor 0
                useexternaltor 1
                cookieauthentication\t1
                CookieAuthFile "/var/run/tor/control.authcookie"
                ControlPort 9151
                ControlPort 127.0.0.1:9051
                """);

        assertThat(config.getUseExternalTor()).contains(true);
        assertThat(config.isCookieAuthentication()).isTrue();
        assertThat(config.getCookieAuthFile()).contains(Paths.get("/var/run/tor/control.authcookie"));
        assertThat(config.getControlHost()).isEqualTo("127.0.0.1");
        assertThat(config.getControlPort()).isEqualTo(9051);
    }

    @Test
    void controlPortForms() {
        assertThat(ExternalTorConfig.parse("ControlPort 9151").getControlHost()).isEqualTo("127.0.0.1");
        assertThat(ExternalTorConfig.parse("ControlPort 10.152.152.10:9051").getControlHost())
                .isEqualTo("10.152.152.10");
        ExternalTorConfig ipv6 = ExternalTorConfig.parse("ControlPort [::1]:9051");
        assertThat(ipv6.getControlHost()).isEqualTo("::1");
        assertThat(ipv6.getControlPort()).isEqualTo(9051);
        // Without ControlPort, Bisq uses the control port which Tor uses by convention
        assertThat(ExternalTorConfig.parse("UseExternalTor 1").getControlPort()).isEqualTo(9051);
    }

    @Test
    void invalidValuesStopTheStart() {
        assertThatThrownBy(() -> ExternalTorConfig.parse("UseExternalTor yes"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UseExternalTor");
        assertThatThrownBy(() -> ExternalTorConfig.parse("CookieAuthentication true"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ExternalTorConfig.parse("ControlPort unix:/run/tor/control"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unix socket");
        assertThatThrownBy(() -> ExternalTorConfig.parse("ControlPort ::1:9051"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("brackets");
        assertThatThrownBy(() -> ExternalTorConfig.parse("ControlPort 127.0.0.1:auto"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ExternalTorConfig.parse("ControlPort 70000"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ExternalTorConfig.parse("ControlPort"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
