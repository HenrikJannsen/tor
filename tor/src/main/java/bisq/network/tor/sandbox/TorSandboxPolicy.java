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
import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The sandbox policy of the embedded Tor: the template of the platform from the resources {@code sandy/policy/}, with
 * the values of this start. The template decides how strongly Tor is isolated and on which hosts sandy may fall back to
 * a weaker level; this class only fills in paths, ports and names. See the README of the Tor library.
 * <p>
 * Tor never starts other processes in the sandbox: with pluggable transports, which are programs that Tor starts,
 * Bisq runs Tor without the sandbox (see TorSandboxStatus). So a compromised Tor cannot leave a process behind which
 * outlives it.
 */
public final class TorSandboxPolicy {
    private static final String TEMPLATE_DIR = "sandy/policy/";
    private static final String LOOPBACK = "127.0.0.1";
    private static final String APP_CONTAINER_NAME_SUFFIX = ".tor.";

    private TorSandboxPolicy() {
    }

    /**
     * @param ports         the control and SOCKS listeners, and the port of sandy's egress broker
     * @param applicationId a short name of the application, for example bisq1 or bisq2. On Windows the name of the
     *                      AppContainer starts with it, so that its entries in the access control lists can be
     *                      attributed.
     */
    public static SandyPolicy create(OS os,
                                     TorDirectories directories,
                                     TorListenerPorts ports,
                                     List<SandyPolicy.ForwardedPort> forwardedPorts,
                                     Map<String, String> torEnvironment,
                                     List<Path> executablePaths,
                                     String applicationId) {
        checkArgument(ports.egress().isPresent(), "The sandbox needs the port of the egress broker");
        // sandy grants read and execute on the program file. Tor reads its libraries, GeoIP files and torrc-defaults in
        // the binary directory; of these, only executablePaths may also be executed. Its OpenSSL reads the empty
        // configuration which OPENSSL_CONF names.
        List<Path> readPaths = List.of(directories.getTorrcPath(),
                directories.getBinaryDirPath(),
                directories.getOpenSslConfigPath());

        Map<String, String> values = new HashMap<>();
        values.put("read", PolicyTemplate.paths(readPaths));
        values.put("read_exec", PolicyTemplate.paths(executablePaths));
        values.put("data", PolicyTemplate.path(directories.getDataDirPath()));
        values.put("egress_port", Integer.toString(ports.egress().getAsInt()));
        values.put("control_listen", PolicyTemplate.string(LOOPBACK + ":" + ports.control().outerPort()));
        values.put("control_port", Integer.toString(ports.control().innerPort()));
        values.put("socks_listen", PolicyTemplate.string(LOOPBACK + ":" + ports.socks().outerPort()));
        values.put("socks_port", Integer.toString(ports.socks().innerPort()));
        values.put("forward", "[" + forwardedPorts.stream()
                .map(port -> "{ port = " + port.innerPort() + ", to = " +
                        PolicyTemplate.string(LOOPBACK + ":" + port.outerPort()) + " }")
                .collect(Collectors.joining(", ")) + "]");
        values.put("environment", PolicyTemplate.table(torEnvironment));
        if (os == OS.WINDOWS) {
            values.put("appcontainer_name",
                    PolicyTemplate.bare(appContainerName(applicationId, directories.getBaseDirPath())));
        }
        String toml = PolicyTemplate.render(readTemplate(templateName(os)), values);
        return new SandyPolicy(toml, directories.getDataDirPath());
    }

    private static String templateName(OS os) {
        return switch (os) {
            case LINUX -> "linux.toml";
            case MAC_OS -> "macos.toml";
            case WINDOWS -> "windows.toml";
            default -> throw new IllegalArgumentException("sandy has no sandbox for " + os);
        };
    }

    private static String readTemplate(String name) {
        try (InputStream inputStream = TorSandboxPolicy.class.getClassLoader()
                .getResourceAsStream(TEMPLATE_DIR + name)) {
            if (inputStream == null) {
                throw new IllegalStateException("Missing resource " + TEMPLATE_DIR + name);
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * The files of the bundled Tor that must be executable besides the Tor binary, which sandy makes executable
     * itself: the libraries that the loader maps as code, {@code *.so*} on Linux, {@code *.dylib} on macOS and
     * {@code *.dll} on Windows (the Windows bundle has none today). On Linux the view of sandy mounts every other path
     * without execute, so also the libraries which the loader finds through {@code LD_LIBRARY_PATH} need it. The
     * binary directory also holds the
     * pluggable transports, {@code tor-gencert} on Windows, GeoIP files and {@code torrc-defaults}; without this list
     * all of them would be executable.
     */
    public static List<Path> executablePaths(OS os, TorDirectories directories) {
        return libraries(os, directories.getBinaryDirPath());
    }

    private static List<Path> libraries(OS os, Path binaryDirPath) {
        Predicate<String> isLibrary = switch (os) {
            case LINUX -> name -> name.endsWith(".so") || name.contains(".so.");
            case MAC_OS -> name -> name.endsWith(".dylib");
            case WINDOWS -> name -> name.endsWith(".dll");
            default -> name -> false;
        };
        if (!Files.isDirectory(binaryDirPath)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(binaryDirPath)) {
            return files.filter(Files::isRegularFile)
                    .filter(path -> isLibrary.test(path.getFileName().toString()))
                    .sorted()
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * One AppContainer per Tor directory. sandy refuses two concurrent runs with different policies under one name,
     * and two Bisq instances with different data directories have different policies. The name has at most 51
     * characters from {@code A-Z a-z 0-9 .}: Windows allows 64, and sandy runs the egress broker in an AppContainer
     * whose name adds 13 characters. The template adds a suffix of its own for each fallback level.
     */
    static String appContainerName(String applicationId, Path baseDirPath) {
        checkArgument(applicationId.matches("[A-Za-z0-9]{1,14}"), "Invalid application ID: " + applicationId);
        String normalizedPath = baseDirPath.toAbsolutePath().normalize().toString().toLowerCase(Locale.ROOT);
        byte[] hash = Sha256Sums.newSha256Digest().digest(normalizedPath.getBytes(StandardCharsets.UTF_8));
        return applicationId + APP_CONTAINER_NAME_SUFFIX +
                BaseEncoding.base16().lowerCase().encode(hash).substring(0, 32);
    }
}
