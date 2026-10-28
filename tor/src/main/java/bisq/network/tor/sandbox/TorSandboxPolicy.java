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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The sandbox policy of the embedded Tor: the template of the platform from the resources {@code sandy/policy/}, with
 * the values of this start. The template decides how strongly Tor is isolated and on which hosts sandy may fall back to
 * a weaker level; this class only fills in paths, ports and names. See the README of the Tor library.
 * <p>
 * Without pluggable transports Tor cannot start any process in its sandbox. With them, the template of the transports
 * lets Tor start their programs, and sandy ends them with Tor. Transports that connect only to the IP address of their
 * bridge keep the network of the sandbox, which they leave through the egress broker; the others resolve names or use
 * UDP, and the broker carries neither, so they get the network of the host.
 */
public final class TorSandboxPolicy {
    private static final String TEMPLATE_DIR = "sandy/policy/";
    private static final String LOOPBACK = "127.0.0.1";
    private static final String APP_CONTAINER_NAME_SUFFIX = ".tor.";
    // obfs4 connects only to the IP address of its bridge, through the egress broker when Tor passes it as TOR_PT_PROXY
    // (measured). meek_lite and webtunnel pass names to the broker, which refuses them, snowflake needs UDP, and
    // conjure exits when it gets a proxy.
    private static final Set<String> BROKERED_TRANSPORTS = Set.of("obfs4");
    // The transports which verify the certificate of their server with the certificate verifier of macOS, a Mach
    // service of trustd: webtunnel (measured), snowflake and conjure, whose Go TLS uses the system roots (not
    // measured). obfs4 uses no TLS, and meek_lite verifies with a root certificate of its own (measured).
    private static final Set<String> SYSTEM_TLS_TRANSPORTS = Set.of("webtunnel", "snowflake", "conjure");
    private static final String MACOS_TRUST_AGENT = "com.apple.trustd.agent";
    private static final String TRANSPORTS_TEMPLATE_SUFFIX = "-transports.toml";
    private static final String DIRECT_TRANSPORTS_TEMPLATE_SUFFIX = "-transports-direct.toml";

    private TorSandboxPolicy() {
    }

    /**
     * @param ports           the control and SOCKS listeners, and the port of sandy's egress broker
     * @param executablePaths the files of the bundle which Tor may execute besides its binary, see
     *                        {@link #executablePaths(OS, TorDirectories)}
     * @param transports      the pluggable transports which Tor starts, or {@link SandboxedTransports#NONE}
     * @param applicationId   a short name of the application, for example bisq1 or bisq2. On Windows the name of the
     *                        AppContainer starts with it, so that its entries in the access control lists can be
     *                        attributed.
     * @throws IllegalArgumentException if the platform has no sandbox, or no sandbox for the transports
     */
    public static SandyPolicy create(OS os,
                                     TorDirectories directories,
                                     TorListenerPorts ports,
                                     List<SandyPolicy.ForwardedPort> forwardedPorts,
                                     Map<String, String> torEnvironment,
                                     List<Path> executablePaths,
                                     SandboxedTransports transports,
                                     String applicationId) {
        checkArgument(ports.egress().isPresent(), "The sandbox needs the port of the egress broker");
        String templateName = templateName(os, transports);
        // sandy grants read and execute on the program file. Tor reads its libraries, GeoIP files and torrc-defaults in
        // the binary directory; of these, only executablePaths may also be executed. Its OpenSSL reads the empty
        // configuration which OPENSSL_CONF names.
        List<Path> readPaths = List.of(directories.getTorrcPath(),
                directories.getBinaryDirPath(),
                directories.getOpenSslConfigPath());
        // Tor starts a bundled transport by its path relative to the binary directory, because the torrc cannot hold
        // a path with white space (PluggableTransportPrograms), so that directory is its working directory then.
        Path workingDirPath = transports.isEmpty() ? directories.getDataDirPath() : directories.getBinaryDirPath();
        List<Path> readExecPaths = new ArrayList<>(executablePaths);
        readExecPaths.addAll(transports.programPaths());

        Map<String, String> values = new HashMap<>();
        values.put("read", PolicyTemplate.paths(readPaths));
        values.put("read_exec", PolicyTemplate.paths(readExecPaths));
        values.put("data", PolicyTemplate.path(directories.getDataDirPath()));
        // The templates of transports that connect directly have no egress broker.
        if (!templateName.endsWith(DIRECT_TRANSPORTS_TEMPLATE_SUFFIX)) {
            values.put("egress_port", Integer.toString(ports.egress().getAsInt()));
        }
        values.put("control_listen", PolicyTemplate.string(LOOPBACK + ":" + ports.control().outerPort()));
        values.put("control_port", Integer.toString(ports.control().innerPort()));
        values.put("socks_listen", PolicyTemplate.string(LOOPBACK + ":" + ports.socks().outerPort()));
        values.put("socks_port", Integer.toString(ports.socks().innerPort()));
        values.put("forward", "[" + forwardedPorts.stream()
                .map(port -> "{ port = " + port.innerPort() + ", to = " +
                        PolicyTemplate.string(LOOPBACK + ":" + port.outerPort()) + " }")
                .collect(Collectors.joining(", ")) + "]");
        values.put("environment", PolicyTemplate.table(torEnvironment));
        // The template of the transports on macOS. Tor itself verifies no certificate through the system.
        if (os == OS.MAC_OS && !transports.isEmpty()) {
            boolean needsTrustAgent = transports.transportNames().stream().anyMatch(SYSTEM_TLS_TRANSPORTS::contains);
            values.put("mach_services", needsTrustAgent ? "[" + PolicyTemplate.string(MACOS_TRUST_AGENT) + "]" : "[]");
        }
        if (os == OS.WINDOWS) {
            values.put("appcontainer_name",
                    PolicyTemplate.bare(appContainerName(applicationId, directories.getBaseDirPath())));
        }
        String toml = PolicyTemplate.render(readTemplate(templateName), values);
        return new SandyPolicy(toml, workingDirPath);
    }

    /**
     * The template of the platform, of its transports through the egress broker if all transports are brokered, or
     * of its transports with the network of the host. A platform without a template for brokered transports uses the
     * one for direct transports: on macOS the private network of sandy has no loopback on which Tor reaches its
     * transports. A platform without either cannot run transports in the sandbox: on Windows Tor cannot create the
     * named pipes to its transports in an AppContainer (measured).
     */
    static String templateName(OS os, SandboxedTransports transports) {
        String platform = switch (os) {
            case LINUX -> "linux";
            case MAC_OS -> "macos";
            case WINDOWS -> "windows";
            default -> throw new IllegalArgumentException("sandy has no sandbox for " + os);
        };
        String platformName = switch (os) {
            case MAC_OS -> "macOS";
            case WINDOWS -> "Windows";
            default -> "Linux";
        };
        if (transports.isEmpty()) {
            return platform + ".toml";
        }
        String brokered = platform + TRANSPORTS_TEMPLATE_SUFFIX;
        if (BROKERED_TRANSPORTS.containsAll(transports.transportNames()) && hasTemplate(brokered)) {
            return brokered;
        }
        String direct = platform + DIRECT_TRANSPORTS_TEMPLATE_SUFFIX;
        if (hasTemplate(direct)) {
            return direct;
        }
        throw new IllegalArgumentException("Tor cannot start pluggable transports in its sandbox on " + platformName +
                ", so the bridges with the transports " + String.join(", ", sorted(transports.transportNames())) +
                " cannot be used in the sandbox.");
    }

    private static List<String> sorted(Set<String> names) {
        return names.stream().sorted().toList();
    }

    private static boolean hasTemplate(String name) {
        return TorSandboxPolicy.class.getClassLoader().getResource(TEMPLATE_DIR + name) != null;
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
