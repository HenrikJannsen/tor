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

package bisq.network.tor.sandbox;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The sandy policy of a program, given as command line options. Only the options Bisq needs are supported. All
 * security relevant settings are passed explicitly, so the policy does not depend on the defaults of sandy.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class SandyPolicy {
    private static final String LOOPBACK = "127.0.0.1";

    /**
     * sandy listens on {@code outerPort} outside the sandbox and relays each connection to {@code innerPort}, where
     * the program listens.
     */
    public record ExposedPort(int outerPort, int innerPort) {
        public ExposedPort {
            checkPort(outerPort);
            checkPort(innerPort);
        }
    }

    /**
     * The program connects to {@code innerPort} and sandy relays each connection to {@code outerPort} outside the
     * sandbox.
     */
    public record ForwardedPort(int innerPort, int outerPort) {
        public ForwardedPort {
            checkPort(innerPort);
            checkPort(outerPort);
        }
    }

    /**
     * Which processes the program may send signals to.
     */
    public enum SignalScope {
        // Only processes in the same sandbox. On Linux this needs Landlock ABI 6 (Linux 6.12).
        ISOLATED("isolated"),
        // Every process of the user.
        ANY("any");

        @Getter
        private final String optionValue;

        SignalScope(String optionValue) {
            this.optionValue = optionValue;
        }
    }

    private final List<Path> readPaths;
    private final List<Path> readExecPaths;
    private final List<Path> readWritePaths;
    private final boolean ipNetworkAllowed;
    private final SignalScope signalScope;
    // With false, the program cannot start processes, so nothing it starts can outlive it.
    private final boolean childProcessesAllowed;
    private final List<ExposedPort> exposedPorts;
    private final List<ForwardedPort> forwardedPorts;
    private final Map<String, String> environment;
    private final Path workingDirPath;
    private final Optional<String> appContainerName;

    public SandyPolicy(List<Path> readPaths,
                       List<Path> readExecPaths,
                       List<Path> readWritePaths,
                       boolean ipNetworkAllowed,
                       SignalScope signalScope,
                       boolean childProcessesAllowed,
                       List<ExposedPort> exposedPorts,
                       List<ForwardedPort> forwardedPorts,
                       Map<String, String> environment,
                       Path workingDirPath,
                       Optional<String> appContainerName) {
        this.readPaths = List.copyOf(readPaths);
        this.readExecPaths = List.copyOf(readExecPaths);
        this.readWritePaths = List.copyOf(readWritePaths);
        this.ipNetworkAllowed = ipNetworkAllowed;
        this.signalScope = signalScope;
        this.childProcessesAllowed = childProcessesAllowed;
        this.exposedPorts = List.copyOf(exposedPorts);
        this.forwardedPorts = List.copyOf(forwardedPorts);
        this.environment = new TreeMap<>(environment);
        this.workingDirPath = workingDirPath;
        this.appContainerName = appContainerName;

        checkArgument(ipNetworkAllowed || (exposedPorts.isEmpty() && forwardedPorts.isEmpty()),
                "Exposed and forwarded ports need IP networking");
        this.environment.keySet().forEach(name ->
                checkArgument(!name.isEmpty() && !name.contains("="), "Invalid environment variable name: " + name));
    }

    public SandyPolicy withSignalScope(SignalScope signalScope) {
        return new SandyPolicy(readPaths, readExecPaths, readWritePaths, ipNetworkAllowed, signalScope,
                childProcessesAllowed, exposedPorts, forwardedPorts, environment, workingDirPath, appContainerName);
    }

    /**
     * The options for {@code sandy run} and {@code sandy check}, without the program.
     */
    public List<String> toOptions() {
        List<String> options = new ArrayList<>();
        readPaths.forEach(path -> addOption(options, "--read", absolute(path)));
        readExecPaths.forEach(path -> addOption(options, "--read-exec", absolute(path)));
        readWritePaths.forEach(path -> addOption(options, "--read-write", absolute(path)));
        addOption(options, "--system", "minimal");
        addOption(options, "--ip", ipNetworkAllowed ? "all" : "none");
        // A program that can reach the Unix sockets of the user can reach the D-Bus session bus, and through the
        // systemd user manager it can start commands outside the sandbox.
        addOption(options, "--unix-sockets", "none");
        addOption(options, "--signals", signalScope.getOptionValue());
        addOption(options, "--linux-path-metadata", "deny");
        addOption(options, "--children", childProcessesAllowed ? "allowed" : "none");
        exposedPorts.forEach(port ->
                addOption(options, "--expose", LOOPBACK + ":" + port.outerPort() + "=" + port.innerPort()));
        forwardedPorts.forEach(port ->
                addOption(options, "--forward", port.innerPort() + "=" + LOOPBACK + ":" + port.outerPort()));
        environment.forEach((name, value) -> addOption(options, "--set-env", name + "=" + value));
        addOption(options, "--cwd", absolute(workingDirPath));
        appContainerName.ifPresent(name -> addOption(options, "--appcontainer", name));
        return options;
    }

    private static void addOption(List<String> options, String name, String value) {
        options.add(name);
        options.add(value);
    }

    private static String absolute(Path path) {
        return path.toAbsolutePath().normalize().toString();
    }

    private static void checkPort(int port) {
        checkArgument(port > 0 && port <= 65535, "Invalid port: " + port);
    }
}
