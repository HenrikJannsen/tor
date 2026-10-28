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

import bisq.network.tor.common.platform.OS;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorListenerPorts;
import bisq.network.tor.process.TorListenerPorts.PortMapping;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorSandboxPolicyTest {
    private static final TorDirectories DIRECTORIES =
            new TorDirectories(Paths.get("").toAbsolutePath().resolve("app").resolve("tor"));
    private static final TorListenerPorts PORTS = new TorListenerPorts(new PortMapping(41001, 41002),
            new PortMapping(41003, 41004), OptionalInt.of(41009));

    private static String quoted(Path path) {
        return PolicyTemplate.path(path);
    }

    /**
     * The template decides how strongly Tor is isolated; the policy gets only the values of the start: the paths, the
     * ports, the forwarded targets and the environment.
     */
    @Test
    void bundledTorOfLinux() {
        List<SandyPolicy.ForwardedPort> forwardedPorts = List.of(new SandyPolicy.ForwardedPort(41005, 41006),
                new SandyPolicy.ForwardedPort(41007, 41008));
        Map<String, String> environment = Map.of("OPENSSL_CONF", DIRECTORIES.getOpenSslConfigPath().toString());
        List<Path> executablePaths = List.of(DIRECTORIES.getBinaryDirPath().resolve("libssl.so.3"));
        SandyPolicy policy = TorSandboxPolicy.create(OS.LINUX, DIRECTORIES, PORTS, forwardedPorts, environment,
                executablePaths, "bisq2");

        String toml = policy.toml();
        assertThat(toml).doesNotContain("@")
                // Tor reads its bundle and the empty configuration of its OpenSSL, and executes only the libraries.
                .contains("read = [" + quoted(DIRECTORIES.getTorrcPath()) + ", " +
                        quoted(DIRECTORIES.getBinaryDirPath()) + ", " + quoted(DIRECTORIES.getOpenSslConfigPath()) +
                        "]\n")
                .contains("read_exec = [" + quoted(executablePaths.get(0)) + "]\n")
                .contains("read_write = [" + quoted(DIRECTORIES.getDataDirPath()) + "]\n")
                .contains("egress = { port = 41009, reach = \"public\" }\n")
                .contains("{ listen = \"127.0.0.1:41002\", port = 41001 }")
                .contains("{ listen = \"127.0.0.1:41004\", port = 41003 }")
                .contains("forward = [{ port = 41005, to = \"127.0.0.1:41006\" }, " +
                        "{ port = 41007, to = \"127.0.0.1:41008\" }]\n")
                .contains("set = { \"OPENSSL_CONF\" = " + PolicyTemplate.string(environment.get("OPENSSL_CONF")) +
                        " }\n")
                .contains("ip = \"private\"\n")
                .contains("view = \"policy\"\n")
                .contains("children = \"none\"\n")
                .contains("end_with_parent = true\n")
                // The levels of Linux, in the order sandy tries them
                .containsSubsequence("name = \"contained\"", "name = \"host-network\"",
                        "name = \"host-network-signals\"")
                // Never a grant of /proc: it would cost the PID namespace of the contained level.
                .doesNotContain("/proc");
        assertThat(policy.workingDirPath()).isEqualTo(DIRECTORIES.getDataDirPath());
    }

    @Test
    void bundledTorReadsItsBinaryDirectoryAndItsOpenSslConfigurationAndExecutesOnlyTheGivenFiles() {
        Map<String, String> environment = Map.of("OPENSSL_CONF", DIRECTORIES.getOpenSslConfigPath().toString());
        List<Path> executablePaths = List.of(DIRECTORIES.getBinaryDirPath().resolve("libevent-2.1.7.dylib"));

        SandyPolicy policy = TorSandboxPolicy.create(OS.MAC_OS, DIRECTORIES, PORTS, List.of(), environment,
                executablePaths, "bisq2");

        assertThat(policy.toml()).doesNotContain("@")
                .contains("read = [" + quoted(DIRECTORIES.getTorrcPath()) + ", " +
                        quoted(DIRECTORIES.getBinaryDirPath()) + ", " + quoted(DIRECTORIES.getOpenSslConfigPath()) +
                        "]\n")
                .contains("read_exec = [" + quoted(executablePaths.get(0)) + "]\n")
                .contains("set = { \"OPENSSL_CONF\" = " + PolicyTemplate.string(environment.get("OPENSSL_CONF")) +
                        " }\n")
                .contains("relays = \"ipv4\"\n")
                .contains("name = \"host-network\"")
                .doesNotContain("name = \"contained\"")
                // Tor itself verifies no certificate through the system.
                .doesNotContain("mach_services");
        // Tor may write only its data directory, which holds neither the bundle nor the torrc.
        assertThat(DIRECTORIES.getBinaryDirPath().startsWith(DIRECTORIES.getDataDirPath())).isFalse();
    }

    @Test
    void windowsNeedsAnAppContainerPerTorDirectoryAndLevel() {
        String name = TorSandboxPolicy.appContainerName("bisq1", DIRECTORIES.getBaseDirPath());

        SandyPolicy policy = TorSandboxPolicy.create(OS.WINDOWS, DIRECTORIES, PORTS, List.of(), Map.of(), List.of(),
                "bisq1");

        assertThat(policy.toml()).doesNotContain("@")
                .contains("appcontainer_name = \"" + name + "\"\n")
                .contains("windows.appcontainer_name = \"" + name + ".h\"\n")
                .contains("win32k = \"allow\"\n")
                // Windows cannot hide the paths outside the policy.
                .doesNotContain("view =");
    }

    @Test
    void theSandboxNeedsThePortOfTheEgressBroker() {
        TorListenerPorts withoutEgress = new TorListenerPorts(new PortMapping(41001, 41002),
                new PortMapping(41003, 41004));

        assertThatThrownBy(() -> TorSandboxPolicy.create(OS.LINUX, DIRECTORIES, withoutEgress, List.of(), Map.of(),
                List.of(), "bisq2"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /**
     * The binary directory of the bundled Tor as the Tor Expert Bundle fills it. Only the libraries that the loader
     * maps as code may be executed besides Tor itself; the programs of the pluggable transports only when Tor uses
     * them (see the tests of the transports).
     */
    @Test
    void executablePathsOfTheBundledTor(@TempDir Path tempDir) throws IOException {
        TorDirectories directories = new TorDirectories(tempDir.resolve("tor"));
        Path binaryDir = directories.getBinaryDirPath();
        Path pluggableTransportsDir = directories.getPluggableTransportsDirPath();
        Files.createDirectories(pluggableTransportsDir);
        for (String name : List.of("tor", "tor.exe", "tor-gencert.exe", "libevent-2.1.7.dylib", "libssl.so.3",
                "geoip", "geoip6", "torrc-defaults")) {
            Files.writeString(binaryDir.resolve(name), "");
        }
        for (String name : List.of("lyrebird", "conjure-client", "pt_config.json")) {
            Files.writeString(pluggableTransportsDir.resolve(name), "");
        }

        assertThat(TorSandboxPolicy.executablePaths(OS.MAC_OS, directories))
                .containsExactly(binaryDir.resolve("libevent-2.1.7.dylib"));
        // On Linux the view of sandy mounts everything else without execute, so the libraries need it too.
        assertThat(TorSandboxPolicy.executablePaths(OS.LINUX, directories))
                .containsExactly(binaryDir.resolve("libssl.so.3"));
        // Windows has no libraries in the bundle.
        assertThat(TorSandboxPolicy.executablePaths(OS.WINDOWS, directories)).isEmpty();
        Files.writeString(binaryDir.resolve("zlib1.dll"), "");
        assertThat(TorSandboxPolicy.executablePaths(OS.WINDOWS, directories))
                .containsExactly(binaryDir.resolve("zlib1.dll"));
    }

    @Test
    void appContainerNameIsValidAndDependsOnTheApplicationAndTheDirectory() {
        Path base = Paths.get("").toAbsolutePath().resolve("Bisq2").resolve("tor");
        String name = TorSandboxPolicy.appContainerName("bisq2", base);

        assertThat(name).matches("[A-Za-z0-9._ -]{1,64}").startsWith("bisq2.tor.");
        // sandy names the AppContainer of the egress broker with 13 more characters, which Windows limits to 64.
        assertThat(TorSandboxPolicy.appContainerName("a".repeat(14), base)).hasSize(51);
        assertThatThrownBy(() -> TorSandboxPolicy.appContainerName("a".repeat(15), base))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(TorSandboxPolicy.appContainerName("bisq2", base)).isEqualTo(name);
        // Windows paths are not case sensitive.
        assertThat(TorSandboxPolicy.appContainerName("bisq2", Paths.get(base.toString().toUpperCase()))).isEqualTo(name);
        assertThat(TorSandboxPolicy.appContainerName("bisq2", base.resolveSibling("tor2"))).isNotEqualTo(name);
        assertThat(TorSandboxPolicy.appContainerName("bisq1", base)).startsWith("bisq1.tor.");
        assertThatThrownBy(() -> TorSandboxPolicy.appContainerName("bisq 1", base))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
