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

package bisq.network.tor.local_network;

import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.platform.OS;
import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.common.torrc.TorrcConfigGenerator;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.installer.TorInstaller;
import bisq.network.tor.local_network.da.DirectoryAuthorityFactory;
import bisq.network.tor.local_network.torrc.TestNetworkTorrcGeneratorFactory;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.LdPreload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class TorNetwork {

    private final Path rootDataDirPath;
    private final DirectoryAuthorityFactory dirAuthFactory = new DirectoryAuthorityFactory();
    private final Set<TorNode> directoryAuthorities = new HashSet<>();
    private final Set<TorNode> relays = new HashSet<>();
    private final Set<TorNode> clients = new HashSet<>();

    // TODO Never queried
    private final Set<Process> allTorProcesses = new HashSet<>();

    private int dirAuthIndex;
    private int relayIndex;
    private int clientIndex;

    public TorNetwork(Path rootDataDirPath) {
        this.rootDataDirPath = rootDataDirPath;
    }

    public TorNetwork addDirAuth(String passphrase) throws IOException, InterruptedException {
        String nickname = "da" + dirAuthIndex++;

        Path nodeDataDirPath = rootDataDirPath.resolve(nickname);
        createDataDirIfNotPresent(nodeDataDirPath);

        var dirAuth = TorNode.builder()
                .type(TorNode.Type.DIRECTORY_AUTHORITY)
                .nickname(nickname)
                .dataDirPath(nodeDataDirPath)
                .orPort(FreePorts.find())
                .dirPort(FreePorts.find())
                .build();
        dirAuthFactory.createDirectoryAuthority(dirAuth, passphrase);
        directoryAuthorities.add(dirAuth);

        return this;
    }

    public TorNetwork addRelay() {
        String nickname = "relay" + relayIndex++;

        Path nodeDataDirPath = rootDataDirPath.resolve(nickname);
        createDataDirIfNotPresent(nodeDataDirPath);

        TorNode firstRelay = TorNode.builder()
                .type(TorNode.Type.RELAY)
                .nickname(nickname)
                .dataDirPath(nodeDataDirPath)

                .orPort(FreePorts.find())
                .dirPort(FreePorts.find())

                .build();
        relays.add(firstRelay);
        return this;
    }

    public TorNetwork addClient() {
        String nickname = "client" + clientIndex++;

        Path nodeDataDirPath = rootDataDirPath.resolve(nickname);
        createDataDirIfNotPresent(nodeDataDirPath);

        TorNode firstClient = TorNode.builder()
                .type(TorNode.Type.CLIENT)
                .nickname(nickname)
                .dataDirPath(nodeDataDirPath)

                .orPort(FreePorts.find())
                .dirPort(FreePorts.find())

                .build();
        clients.add(firstClient);
        return this;
    }

    public void start() throws IOException {
        generateTorrcFiles();
        installTor();
        startProcesses();
    }

    private void createDataDirIfNotPresent(Path nodeDataDirPath) {
        if (Files.exists(nodeDataDirPath)) {
            return;
        }

        try {
            FileUtils.createDirectory(nodeDataDirPath);
        } catch (IOException e) {
            throw new IllegalStateException("Couldn't create data directory: " + nodeDataDirPath.toAbsolutePath(), e);
        }
    }

    private void generateTorrcFiles() {
        Set<TorNode> allDAs = dirAuthFactory.getAllDirectoryAuthorities();
        for (TorNode da : allDAs) {
            TorrcConfigGenerator torDaTorrcGenerator = TestNetworkTorrcGeneratorFactory.directoryTorrcGenerator(da);
            Map<String, String> torrcConfigs = torDaTorrcGenerator.generate();
            generateTorrc(da, torrcConfigs, allDAs);
        }

        for (TorNode relay : relays) {
            TorrcConfigGenerator relayTorrcGenerator = TestNetworkTorrcGeneratorFactory.relayTorrcGenerator(relay);
            Map<String, String> torrcConfigs = relayTorrcGenerator.generate();
            generateTorrc(relay, torrcConfigs, allDAs);
        }

        for (TorNode client : clients) {
            TorrcConfigGenerator clientTorrcGenerator = TestNetworkTorrcGeneratorFactory.clientTorrcGenerator(client);
            Map<String, String> torrcConfigs = clientTorrcGenerator.generate();
            generateTorrc(client, torrcConfigs, allDAs);
        }
    }

    private void installTor() {
        Path torBinaryDirPath = rootDataDirPath.resolve("tor_binary");
        var torInstaller = new TorInstaller(torBinaryDirPath);
        torInstaller.installIfNotUpToDate();
    }

    private void startProcesses() throws IOException {
        for (TorNode directoryAuthority : directoryAuthorities) {
            Process process = createAndStartTorProcess(directoryAuthority);
            allTorProcesses.add(process);
        }

        for (TorNode relay : relays) {
            Process process = createAndStartTorProcess(relay);
            allTorProcesses.add(process);
        }

        for (TorNode client : clients) {
            Process process = createAndStartTorProcess(client);
            allTorProcesses.add(process);
        }
    }

    private Process createAndStartTorProcess(TorNode torNode) throws IOException {
        Path torBinaryDirPath = rootDataDirPath.resolve("tor_binary");
        boolean isLinux = OS.isLinux();
        Optional<Path> systemTorPath = isLinux ? EmbeddedTorProcess.getSystemTorPath() : Optional.empty();
        String absoluteTorBinaryPath = torBinaryPath(torBinaryDirPath, isLinux, OS.isWindows(), systemTorPath)
                .toAbsolutePath()
                .toString();
        String absoluteTorrcPathAsString = torNode.getTorrcPath()
                .toAbsolutePath()
                .toString();
        var processBuilder = new ProcessBuilder(absoluteTorBinaryPath, "-f", absoluteTorrcPathAsString);

        Map<String, String> environment = processBuilder.environment();
        LdPreload.applyToEnvironment(environment, torBinaryDirPath);

        processBuilder.redirectError(ProcessBuilder.Redirect.DISCARD);
        processBuilder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        return processBuilder.start();
    }

    /**
     * The Tor binary of the nodes, chosen as TorService chooses it: on Linux the tor of the system, because the bundle
     * has no tor there, otherwise the bundled tor.
     *
     * @param systemTorPath the tor in PATH, if any
     * @throws IllegalStateException on Linux without a tor in PATH
     */
    static Path torBinaryPath(Path torBinaryDirPath, boolean isLinux, boolean isWindows, Optional<Path> systemTorPath) {
        if (isLinux) {
            return systemTorPath.orElseThrow(() -> new IllegalStateException("The bundle has no tor for Linux and " +
                    "PATH names no tor. Install the tor of the system."));
        }
        return torBinaryDirPath.resolve(isWindows ? "tor.exe" : "tor");
    }

    private void generateTorrc(TorNode torNode, Map<String, String> torrcConfigs, Set<TorNode> allDAs) {
        if (Files.exists(torNode.getTorrcPath())) {
            return;
        }

        Set<DirectoryAuthority> directoryAuthorities = allDAs.stream()
                .map(TorNode::toDirectoryAuthority)
                .collect(Collectors.toSet());

        var torrcFileGenerator = new TorrcFileGenerator(torNode.getTorrcPath(), torrcConfigs, directoryAuthorities);
        torrcFileGenerator.generate();
    }
}
