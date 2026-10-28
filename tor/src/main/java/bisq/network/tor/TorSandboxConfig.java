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

import com.typesafe.config.Config;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The configuration of the sandbox of the embedded Tor. The library runs the Tor which it starts inside sandy if the
 * sandbox is enabled and the host can enforce it. Pluggable transports, programs which Tor starts for bridges, run in
 * the sandbox only if the configuration allows them; otherwise a sandboxed start with them is refused.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class TorSandboxConfig {
    // The path of the configuration of Bisq 2
    public static final String BISQ2_CONFIG_PATH = "application.network.configByTransportType.tor.sandbox";
    static final int DEFAULT_ONION_SERVICE_PORT_POOL_SIZE = 32;
    private static final int MAX_ONION_SERVICE_PORT_POOL_SIZE = 1024;

    public static final TorSandboxConfig DISABLED = new TorSandboxConfig(false, true, false,
            DEFAULT_ONION_SERVICE_PORT_POOL_SIZE, "bisq", "");

    /**
     * Reads the optional block {@code sandbox} of the Tor configuration of Bisq 2. The sandbox is off unless the
     * configuration turns it on, because sandy has no public release which a build could download and package.
     */
    static TorSandboxConfig from(Config torConfig) {
        Config config = torConfig.hasPath("sandbox") ? torConfig.getConfig("sandbox") : null;
        boolean enabled = config != null && config.hasPath("enabled") && config.getBoolean("enabled");
        boolean forwardOnionServicePorts = config == null || !config.hasPath("forwardOnionServicePorts") ||
                config.getBoolean("forwardOnionServicePorts");
        boolean allowPluggableTransports = config != null && config.hasPath("allowPluggableTransports") &&
                config.getBoolean("allowPluggableTransports");
        int onionServicePortPoolSize = config != null && config.hasPath("onionServicePortPoolSize") ?
                config.getInt("onionServicePortPoolSize") :
                DEFAULT_ONION_SERVICE_PORT_POOL_SIZE;
        return new TorSandboxConfig(enabled, forwardOnionServicePorts, allowPluggableTransports,
                onionServicePortPoolSize, "bisq2",
                "Start Bisq with the JVM option -D" + BISQ2_CONFIG_PATH + ".enabled=false to run Tor without the " +
                        "sandbox.");
    }

    // Runs the embedded Tor inside sandy.
    private final boolean enabled;
    // Tor reaches the onion services of Bisq through ports which sandy forwards. The sandbox needs it: Tor has a
    // network of its own there, and on Windows an AppContainer cannot reach the loopback ports of Bisq either.
    private final boolean forwardOnionServicePorts;
    // Tor may start the pluggable transports of the bridges in its sandbox, which then lets it start processes and,
    // for transports that resolve names or use UDP, gives it the network of the host. Off by default.
    private final boolean allowPluggableTransports;
    // The number of onion services which can receive connections through forwarded ports.
    private final int onionServicePortPoolSize;
    // A short name of the application, for example bisq1 or bisq2. The AppContainer of Windows is named after it.
    private final String applicationId;
    // How the user of the application turns the sandbox off, for the error when the sandbox is unavailable
    private final String optOutHint;

    public TorSandboxConfig(boolean enabled,
                            boolean forwardOnionServicePorts,
                            boolean allowPluggableTransports,
                            int onionServicePortPoolSize,
                            String applicationId,
                            String optOutHint) {
        checkArgument(onionServicePortPoolSize > 0 && onionServicePortPoolSize <= MAX_ONION_SERVICE_PORT_POOL_SIZE,
                "onionServicePortPoolSize must be between 1 and " + MAX_ONION_SERVICE_PORT_POOL_SIZE);
        this.enabled = enabled;
        this.forwardOnionServicePorts = forwardOnionServicePorts;
        this.allowPluggableTransports = allowPluggableTransports;
        this.onionServicePortPoolSize = onionServicePortPoolSize;
        this.applicationId = applicationId;
        this.optOutHint = optOutHint;
    }
}
