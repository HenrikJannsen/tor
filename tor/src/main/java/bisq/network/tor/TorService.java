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

import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.platform.LinuxDistribution;
import bisq.network.tor.common.platform.OS;
import bisq.network.tor.common.torrc.BaseTorrcGenerator;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.common.torrc.TorrcSyntax;
import bisq.network.tor.controller.PasswordDigest;
import bisq.network.tor.controller.TorControlAuthenticationFailed;
import bisq.network.tor.controller.TorController;
import bisq.network.tor.installer.TorInstaller;
import bisq.network.tor.onionservice.DirectOnionServiceTargets;
import bisq.network.tor.onionservice.OnionServiceKey;
import bisq.network.tor.onionservice.OnionServiceTargets;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.LdPreload;
import bisq.network.tor.process.LoopbackPorts;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorStartupFailedException;
import bisq.network.tor.process.control_port.ControlPortFileParser;
import com.google.common.annotations.VisibleForTesting;
import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;


@Slf4j
public class TorService {
    private static final long CONTROL_PORT_FILE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(30);
    private static final long CONTROL_PORT_FILE_POLL_INTERVAL_MS = 100;
    private static final String GEOIP_FILE = "GeoIPFile";
    private static final String GEOIP_V6_FILE = "GeoIPv6File";
    // Environment variable to not launch the embedded Tor process
    public static final String TOR_SKIP_LAUNCH = "TOR_SKIP_LAUNCH";

    private final TorTransportConfig transportConfig;
    private final PlatformServices platformServices;
    private final TorDirectories torDirectories;
    // Creates the controller of each start, see createControllerOfTheStart
    private final Supplier<TorController> torControllerFactory;

    private final Object lifecycleLock = new Object();
    // The initialization which runs or succeeded, whose result every caller of initialize gets. Empty before the first
    // initialization, after a failed one, and from the begin of a shutdown on. Guarded by lifecycleLock.
    private Optional<CompletableFuture<Boolean>> initialization = Optional.empty();
    // The shutdown which runs. Guarded by lifecycleLock.
    private Optional<CompletableFuture<Boolean>> runningShutdown = Optional.empty();

    // Written by initialize and by shutdown, which runs on another thread, and read by the API methods
    private volatile TorController torController;
    // Written by initialize, read by the user interface
    @Getter
    private volatile boolean useExternalTor;
    // The version which the running Tor reports. On Linux it is the tor of the system, not the bundled version.
    @Getter
    private volatile Optional<String> torVersion = Optional.empty();

    private volatile Optional<EmbeddedTorProcess> torProcess = Optional.empty();
    private volatile Optional<TorSocksProxyFactory> torSocksProxyFactory = Optional.empty();
    private volatile OnionServiceTargets onionServiceTargets = new DirectOnionServiceTargets(LoopbackPorts.IPV4_LOOPBACK);

    public TorService(TorTransportConfig transportConfig, PlatformServices platformServices) {
        this(transportConfig, platformServices, () -> new TorController(transportConfig.getBootstrapTimeout(),
                transportConfig.getHsUploadTimeout()));
    }

    @VisibleForTesting
    TorService(TorTransportConfig transportConfig,
               PlatformServices platformServices,
               Supplier<TorController> torControllerFactory) {
        this.transportConfig = transportConfig;
        this.platformServices = platformServices;
        this.torDirectories = new TorDirectories(transportConfig.getDataDirPath());
        this.torControllerFactory = () -> createControllerOfTheStart(torControllerFactory);
    }

    /**
     * Starts Tor, or connects to the external Tor, in the thread of the caller. Callers share one initialization: a
     * call while it runs gets its result, and a call after its success gets the success at once. A failure lets the
     * next call start again, also a failure before the connection, for example an invalid external_tor.config. A
     * shutdown while the initialization runs makes it fail. A call during a shutdown waits for the end of the shutdown
     * and then starts again, as a call after a shutdown does.
     *
     * @return a future which completes with true once Tor runs. The caller whose thread runs the start gets a failure
     * thrown; the callers which share the initialization get it in the future.
     */
    public CompletableFuture<Boolean> initialize() {
        CompletableFuture<Boolean> ownInitialization = new CompletableFuture<>();
        Optional<CompletableFuture<Boolean>> sharedInitialization = shareOrBeginInitialization(ownInitialization);
        if (sharedInitialization.isPresent()) {
            return sharedInitialization.get();
        }
        try {
            start();
        } catch (RuntimeException | Error e) {
            synchronized (lifecycleLock) {
                if (isCurrentInitialization(ownInitialization)) {
                    initialization = Optional.empty();
                }
            }
            ownInitialization.completeExceptionally(e);
            throw e;
        }
        boolean isEndedByShutdown;
        synchronized (lifecycleLock) {
            isEndedByShutdown = !isCurrentInitialization(ownInitialization);
        }
        if (isEndedByShutdown) {
            // The shutdown stops what this start created once the future has completed.
            TorStartupFailedException failure = shutDownDuringTheStart();
            ownInitialization.completeExceptionally(failure);
            throw failure;
        }
        ownInitialization.complete(true);
        return ownInitialization;
    }

    // An initialization runs after a running shutdown has ended, never alongside it.
    private Optional<CompletableFuture<Boolean>> shareOrBeginInitialization(CompletableFuture<Boolean> ownInitialization) {
        while (true) {
            CompletableFuture<Boolean> shutdown;
            synchronized (lifecycleLock) {
                if (runningShutdown.isEmpty()) {
                    if (initialization.isPresent()) {
                        return initialization;
                    }
                    initialization = Optional.of(ownInitialization);
                    return Optional.empty();
                }
                shutdown = runningShutdown.get();
            }
            shutdown.handle((result, throwable) -> result).join();
        }
    }

    // Only a shutdown replaces the initialization of a running start.
    private boolean isCurrentInitialization(CompletableFuture<Boolean> ownInitialization) {
        return initialization.isPresent() && initialization.get() == ownInitialization;
    }

    /**
     * A start creates its controller only while no shutdown has ended its initialization. A shutdown before the start
     * had a controller shuts down none of this start, so the start would otherwise start Tor after the shutdown.
     */
    private TorController createControllerOfTheStart(Supplier<TorController> factory) {
        TorController controller = factory.get();
        synchronized (lifecycleLock) {
            if (initialization.isPresent()) {
                return controller;
            }
        }
        runQuietly(controller::shutdown, "Shutdown of the Tor controller failed");
        throw shutDownDuringTheStart();
    }

    private static TorStartupFailedException shutDownDuringTheStart() {
        return new TorStartupFailedException("The Tor service was shut down during its start");
    }

    private void start() {
        makeTorDir();

        ExternalTorConfig externalTorConfig = readExternalTorConfig();

        useExternalTor = evaluateUseExternalTor(externalTorConfig);
        if (useExternalTor) {
            if (connectedToExternalTor(externalTorConfig)) {
                log.info("External Tor will be used");
                return;
            } else if (LinuxDistribution.isWhonix()) {
                // In case we failed at connectedToExternalTor, we do not start the embedded Tor as fallback if we are on Whonix.
                throw new RuntimeException("Bisq runs on a Whonix system but it could not connect to the Whonix system Tor. " +
                        "Please check the Bisq external_tor.config and the system Tor torrc config.");
            } else {
                // In case connectedToExternalTor failed we try embedded Tor (if not running on Whonix)
                useExternalTor = false;
            }
        }

        startEmbeddedTor();
    }

    private void startEmbeddedTor() {
        if (!OS.isLinux()) {
            installTorIfNotUpToDate();
        }

        Path torBinaryPath = getTorBinaryPath();

        if (torController != null) {
            torController.shutdown();
        }
        torController = torControllerFactory.get();

        PasswordDigest hashedControlPassword = PasswordDigest.generateDigest();
        boolean isBundledTor = torDirectories.isBundledTor(torBinaryPath);
        createTorrcConfigFile(hashedControlPassword, isBundledTor);
        if (isBundledTor) {
            createEmptyOpenSslConfig();
        }

        // remove the control port file before we launch tor, just in case it exists from
        // a previous run
        Path controlDirPath = torDirectories.getDataDirPath().resolve(BaseTorrcGenerator.CONTROL_DIR_NAME);
        Path controlPortFilePath = controlDirPath.resolve("control");
        try {
            FileUtils.deleteFileAndWait(controlPortFilePath, 5000);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete tor control port file", e);
        }

        createTorControlDirectory();
        EmbeddedTorProcess embeddedTorProcess = createTorProcess(torBinaryPath);
        torProcess = Optional.of(embeddedTorProcess);
        embeddedTorProcess.start();

        try {
            waitUntilControlPortFileExists(controlPortFilePath, embeddedTorProcess);

            int controlPort = ControlPortFileParser.parse(controlPortFilePath);

            controlPortFilePath.toFile().deleteOnExit();

            torController.initialize(controlPort);
            torController.authenticate(hashedControlPassword);
            torController.verifyHashedControlPassword(hashedControlPassword);
            torController.bootstrap();
            if (!embeddedTorProcess.isAlive()) {
                throw new TorStartupFailedException("Embedded Tor exited during bootstrap. " +
                        embeddedTorProcess.getStartupDiagnostics());
            }

            torVersion = torController.getTorVersion();
            log.info("Tor {} runs with the binary {}", torVersion.orElse("of unknown version"), torBinaryPath);

            int port = torController.getSocksPort();
            torSocksProxyFactory = Optional.of(new TorSocksProxyFactory(port));
        } catch (InterruptedException e) {
            stopEmbeddedTor(embeddedTorProcess);
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for tor control port file to exist", e);
        } catch (IOException e) {
            stopEmbeddedTor(embeddedTorProcess);
            throw new RuntimeException("Error while waiting for tor control port file to exist", e);
        } catch (RuntimeException e) {
            stopEmbeddedTor(embeddedTorProcess);
            throw e;
        }
    }

    private EmbeddedTorProcess createTorProcess(Path torBinaryPath) {
        Consumer<Map<String, String>> environmentAdjuster = torDirectories.isBundledTor(torBinaryPath) ?
                environment -> {
                    LdPreload.applyToEnvironment(environment, torDirectories.getBinaryDirPath());
                    // The OpenSSL of the bundled Tor reads openssl.cnf from a directory of its build below
                    // /var/tmp/dist, where any local user can create files, unless OPENSSL_CONF names another file.
                    // The configuration can load modules into Tor.
                    environment.put("OPENSSL_CONF", torDirectories.getOpenSslConfigPath().toAbsolutePath().toString());
                } :
                environment -> {
                };
        return new EmbeddedTorProcess(createTorCommand(torBinaryPath),
                torDirectories.getBinaryDirPath(),
                environmentAdjuster,
                torDirectories.getStdoutLogPath(),
                torDirectories.getStderrLogPath());
    }

    private List<String> createTorCommand(Path torBinaryPath) {
        String ownerPid = platformServices.getMyPid();
        return EmbeddedTorProcess.torCommand(torBinaryPath, torDirectories.getTorrcPath(), ownerPid);
    }

    private void stopEmbeddedTor(EmbeddedTorProcess embeddedTorProcess) {
        if (torController != null) {
            runQuietly(torController::shutdown, "Shutdown of the Tor controller failed");
        }
        embeddedTorProcess.shutdown();
        torProcess = Optional.empty();
    }

    private static void runQuietly(Runnable runnable, String errorMessage) {
        try {
            runnable.run();
        } catch (RuntimeException e) {
            log.warn(errorMessage, e);
        }
    }

    private void createTorControlDirectory() {
        Path controlDirFilePath = torDirectories.getDataDirPath().resolve(BaseTorrcGenerator.CONTROL_DIR_NAME);
        if (!Files.exists(controlDirFilePath)) {
            try {
                FileUtils.createDirectories(controlDirFilePath);
            } catch (IOException e) {
                throw new TorStartupFailedException("Couldn't create Tor control directory.");
            }
        }
    }

    private boolean evaluateUseExternalTor(ExternalTorConfig externalTorConfig) {
        if (LinuxDistribution.isWhonix()) {
            log.info("Bisq runs on a Whonix system and use the Whonix system Tor");
            return true;
        } else {
            // If environment variable is set we take that.
            String torSkipLaunch = System.getenv(TOR_SKIP_LAUNCH);
            if (torSkipLaunch != null && !torSkipLaunch.trim().isEmpty()) {
                log.info("Environment variable 'TOR_SKIP_LAUNCH' is set to '{}'", torSkipLaunch);
                return torSkipLaunch.equals("1") ||
                        torSkipLaunch.equalsIgnoreCase("true") ||
                        torSkipLaunch.equalsIgnoreCase("yes");
            } else {
                // We check if external_tor.config value is set. If so we use that value.
                // Last we take the value form the JVM config.
                return externalTorConfig.getUseExternalTor().orElse(transportConfig.isUseExternalTor());
            }
        }
    }

    /**
     * Stops Tor, and ends a running initialization, which then fails. The future completes once the start of that
     * initialization has ended, so that no Tor of this service runs then. A call during a shutdown gets that shutdown.
     * The service can be started again.
     */
    public CompletableFuture<Boolean> shutdown() {
        log.info("shutdown");
        CompletableFuture<Boolean> shutdown = new CompletableFuture<>();
        Optional<CompletableFuture<Boolean>> endedInitialization;
        synchronized (lifecycleLock) {
            if (runningShutdown.isPresent()) {
                return runningShutdown.get();
            }
            endedInitialization = initialization;
            initialization = Optional.empty();
            runningShutdown = Optional.of(shutdown);
        }
        CompletableFuture.runAsync(() -> stopTor(endedInitialization), ForkJoinPool.commonPool())
                .whenComplete((nil, throwable) -> {
                    synchronized (lifecycleLock) {
                        runningShutdown = Optional.empty();
                    }
                    if (throwable == null) {
                        shutdown.complete(true);
                    } else {
                        shutdown.completeExceptionally(throwable);
                    }
                });
        return shutdown;
    }

    private void stopTor(Optional<CompletableFuture<Boolean>> endedInitialization) {
        // Ends a running start at its next step: its commands and its wait for the bootstrap fail, and its wait for the
        // control port ends with the process.
        stopControllerAndProcess();
        // Until the start has ended, the fields belong to it, and it may still create a controller or a process.
        endedInitialization.ifPresent(start -> start.handle((result, throwable) -> result).join());
        stopControllerAndProcess();
        torController = null;
        torProcess = Optional.empty();
        onionServiceTargets.close();
        torSocksProxyFactory = Optional.empty();
        torVersion = Optional.empty();
    }

    // Each step runs also when an earlier one fails, so that Tor is stopped in any case.
    private void stopControllerAndProcess() {
        TorController controller = torController;
        if (controller != null) {
            runQuietly(controller::shutdown, "Shutdown of the Tor controller failed");
        }
        torProcess.ifPresent(process -> runQuietly(process::shutdown, "Shutdown of the Tor process failed"));
    }

    public CompletableFuture<String> publishOnionService(int localPort, int onionServicePort, OnionServiceKey onionServiceKey) {
        long ts = System.currentTimeMillis();
        String onionAddress = onionServiceKey.getOnionAddress();
        try {
            // The onion address only at debug level: a log which a user shares must not list the onion services of
            // the user together.
            log.debug("Publish onion service {}:{} (localPort={})", onionAddress, onionServicePort, localPort);
            int torTargetPort = onionServiceTargets.targetPortOf(onionAddress, localPort);
            // The controller publishes each onion address once per connection to Tor, also for concurrent calls.
            torController.publish(onionServiceKey, onionServicePort, torTargetPort);

            log.info("Tor onion service ready. Took {} ms (onionServicePort={}, localPort={})",
                    System.currentTimeMillis() - ts, onionServicePort, localPort);
            log.debug("Onion service {} is ready", onionAddress);

            return CompletableFuture.completedFuture(onionAddress);
        } catch (InterruptedException e) {
            log.warn("Can't create onion service. Thread got interrupted at publishOnionService method", e);
            Thread.currentThread().interrupt(); // Restore interrupted state
            return CompletableFuture.failedFuture(e);
        } catch (IOException e) {
            logPublicationFailure(onionAddress, e);
            return CompletableFuture.failedFuture(e);
        } catch (RuntimeException e) {
            Throwable cause = unwrapCompletionException(e);
            logPublicationFailure(onionAddress, cause);
            return CompletableFuture.failedFuture(cause);
        }
    }

    public CompletableFuture<ServerSocket> publishOnionServiceAndCreateServerSocket(int port, OnionServiceKey onionServiceKey) {
        long ts = System.currentTimeMillis();
        String onionAddress = onionServiceKey.getOnionAddress();
        OnionServiceTargets.Target target;
        try {
            target = onionServiceTargets.bindServerSocket(onionAddress);
        } catch (IOException e) {
            logPublicationFailure(onionAddress, e);
            return CompletableFuture.failedFuture(e);
        }

        try {
            log.debug("Publish onion service {}:{}", onionAddress, port);
            // The controller publishes each onion address once per connection to Tor, also for concurrent calls.
            torController.publish(onionServiceKey, port, target.torTargetPort());

            log.info("Tor onion service ready. Took {} ms (onionServicePort={})", System.currentTimeMillis() - ts, port);
            log.debug("Onion service {} is ready", onionAddress);

            return CompletableFuture.completedFuture(target.serverSocket());
        } catch (InterruptedException e) {
            log.warn("Can't create onion service. Thread got interrupted at publishOnionService method", e);
            closeQuietly(target.serverSocket());
            Thread.currentThread().interrupt(); // Restore interrupted state
            return CompletableFuture.failedFuture(e);
        } catch (RuntimeException e) {
            closeQuietly(target.serverSocket());
            Throwable cause = unwrapCompletionException(e);
            logPublicationFailure(onionAddress, cause);
            return CompletableFuture.failedFuture(cause);
        }
    }

    // The message of a failure can name onion addresses, which link the identities of a user in a log that the user
    // shares. Above debug level only a fixed text and the type of the failure.
    private static void logPublicationFailure(String onionAddress, Throwable cause) {
        log.error("Can't create onion service: {}", cause.getClass().getSimpleName());
        log.debug("Can't create onion service {}", onionAddress, cause);
    }

    // TorController.publish reports a failed publication as a CompletionException with the failure as its cause. The
    // hosts wait on the returned future, so the failure belongs into the future, as for the other failures.
    private static Throwable unwrapCompletionException(RuntimeException e) {
        return e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
    }

    public CompletableFuture<Boolean> isOnionServiceOnlineAsync(String onionUrl) {
        return torController.isOnionServiceOnlineAsync(onionUrl)
                .orTimeout(1, TimeUnit.MINUTES);
    }

    public Socket getSocket(String host, int port, String streamId, int socketTimeout) throws IOException {
        TorSocksProxyFactory socksProxyFactory = torSocksProxyFactory.orElseThrow();
        return socksProxyFactory.getSocket(host, port, streamId, socketTimeout);
    }

    public Socks5Proxy getSocks5Proxy() throws IOException {
        TorSocksProxyFactory socksProxyFactory = torSocksProxyFactory.orElseThrow();
        return socksProxyFactory.getSocks5Proxy();
    }

    private boolean connectedToExternalTor(ExternalTorConfig externalTorConfig) {
        String controlHost = externalTorConfig.getControlHost();
        int controlPort = externalTorConfig.getControlPort();
        if (!isTorControlAvailable(controlHost, controlPort)) {
            log.warn("Couldn't connect to external Tor control server. " +
                    "This could happen if the control port is not correctly set up in 'external_tor.config' file.");
            return false;
        }

        if (torController != null) {
            torController.shutdown();
        }
        torController = torControllerFactory.get();
        torController.initialize(controlPort);

        boolean isAuthenticated = false;
        boolean noCookieAuthenticationRequired = !externalTorConfig.isCookieAuthentication();
        if (noCookieAuthenticationRequired) {
            // No authentication required, but we still need to send an empty
            // AUTHENTICATE call to be able to send control commands
            try {
                torController.authenticate();
                isAuthenticated = true;
            } catch (TorControlAuthenticationFailed e) {
                log.warn("Authentication to Tor Control failed.");
                return false;
            }
        }

        if (!isAuthenticated) {
            if (externalTorConfig.getCookieAuthFile().isPresent()) {
                Path authCookiePath = externalTorConfig.getCookieAuthFile().get();
                try {
                    byte[] authCookie = Files.readAllBytes(authCookiePath);
                    torController.authenticate(authCookie);
                    isAuthenticated = true;
                } catch (TorControlAuthenticationFailed e) {
                    log.warn("Authentication with authCookie failed.");
                } catch (IOException e) {
                    log.warn("Couldn't read the COOKIE_AUTH_FILE '{}' from the config.", authCookiePath);
                }
            } else {
                log.warn("The user did not provide the path to the COOKIE_AUTH_FILE.");
            }
        }

        if (!isAuthenticated) {
            log.info("We try to call authenticate without parameters for the case that authentication is not required.");
            try {
                torController.authenticate();
            } catch (TorControlAuthenticationFailed ex) {
                log.warn("Authentication to Tor Control failed.");
                return false;
            }
        }

        onionServiceTargets.close();
        onionServiceTargets = new DirectOnionServiceTargets(getExternalTorBindAddress());

        torVersion = torController.getTorVersion();
        log.info("The external Tor at {}:{} has version {}", controlHost, controlPort,
                torVersion.orElse("unknown"));

        // We do not call torController.bootstrap as we do not need to bootstrap Tor.
        int port = torController.getSocksPort();
        log.info("Tor control provided SOCKS port: {}", port);
        torSocksProxyFactory = Optional.of(new TorSocksProxyFactory(port));
        return true;
    }

    private ExternalTorConfig readExternalTorConfig() {
        Path torConfigFilePath = torDirectories.getExternalTorConfigPath();
        String torConfig;
        try {
            if (!Files.exists(torConfigFilePath)) {
                torConfig = FileUtils.readStringFromResource("tor/" + TorDirectories.EXTERNAL_TOR_CONFIG_FILE_NAME);
                FileUtils.writeToPath(torConfig, torConfigFilePath, platformServices.supportsPosixPermissions());
            } else {
                torConfig = FileUtils.readUTF8String(torConfigFilePath);
            }
        } catch (IOException e) {
            // Without the file, Bisq cannot know whether the user wants to use an external Tor.
            log.warn("Could not read {}", torConfigFilePath, e);
            throw new IllegalStateException("Could not read " + torConfigFilePath + ": " + e);
        }
        try {
            return ExternalTorConfig.parse(torConfig);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid " + torConfigFilePath + ": " + e.getMessage(), e);
        }
    }

    private boolean isTorControlAvailable(String controlHost, int controlPort) {
        try (Socket socket = new Socket()) {
            var socketAddress = new InetSocketAddress(controlHost, controlPort);
            socket.connect(socketAddress);
            log.info("Test connection to control server of external tor process successful.");
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void makeTorDir() {
        try {
            FileUtils.createDirectories(torDirectories.getBaseDirPath(), platformServices.supportsPosixPermissions());
        } catch (IOException e) {
            log.warn("Couldn't create the Tor directory", e);
            throw new TorStartupFailedException("Couldn't create the Tor directory " +
                    torDirectories.getBaseDirPath() + ": " + e);
        }
    }

    private void waitUntilControlPortFileExists(Path controlPortFilePath,
                                                EmbeddedTorProcess embeddedTorProcess) throws InterruptedException, IOException {
        long start = System.currentTimeMillis();
        while (!Files.exists(controlPortFilePath)) {
            if (!embeddedTorProcess.isAlive()) {
                throw new IOException("Embedded Tor exited before writing control port file. " +
                        embeddedTorProcess.getStartupDiagnostics());
            }
            if (System.currentTimeMillis() - start > CONTROL_PORT_FILE_TIMEOUT_MS) {
                throw new IOException("Control port file did not exist after " + CONTROL_PORT_FILE_TIMEOUT_MS + " ms: " +
                        controlPortFilePath.toAbsolutePath() + ". " + embeddedTorProcess.getStartupDiagnostics());
            }
            Thread.sleep(CONTROL_PORT_FILE_POLL_INTERVAL_MS);
        }
    }

    private Path getTorBinaryPath() {
        if (OS.isLinux()) {
            Optional<Path> systemTorBinaryPath = EmbeddedTorProcess.getSystemTorPath();
            return systemTorBinaryPath.orElseThrow(TorNotInstalledException::new);
        }
        return torDirectories.getBundledTorBinaryPath();
    }

    private void installTorIfNotUpToDate() {
        var torInstaller = new TorInstaller(torDirectories.getBinaryDirPath());
        torInstaller.installIfNotUpToDate();
    }

    private static boolean isSet(Map<String, String> torrcConfigMap, String key) {
        return torrcConfigMap.keySet().stream().anyMatch(existingKey -> TorrcClientConfigFactory.sets(existingKey, key));
    }

    /**
     * The bundled Tor looks for its GeoIP files in a directory of its build below /var/tmp/dist, where any local user
     * can create files, unless the torrc names them. Bisq names the files of the bundle also when one is missing from a
     * damaged installation: Tor then runs without country data instead of reading that directory. A torrc override of
     * the user still applies.
     */
    @VisibleForTesting
    static void putBundledGeoIpFiles(Map<String, String> torrcConfigMap, TorDirectories torDirectories) {
        putIfNotSet(torrcConfigMap, GEOIP_FILE, torDirectories.getBundledGeoIpFilePath());
        putIfNotSet(torrcConfigMap, GEOIP_V6_FILE, torDirectories.getBundledGeoIpv6FilePath());
    }

    private static void putIfNotSet(Map<String, String> torrcConfigMap, String key, Path filePath) {
        if (isSet(torrcConfigMap, key)) {
            return;
        }
        if (!Files.exists(filePath)) {
            log.warn("The Tor bundle has no {}. Tor runs without its country data.", filePath);
        }
        torrcConfigMap.put(key, TorrcSyntax.toValue(filePath.toAbsolutePath().toString()));
    }

    private void createEmptyOpenSslConfig() {
        Path openSslConfigPath = torDirectories.getOpenSslConfigPath();
        try {
            FileUtils.writeToPath("", openSslConfigPath, platformServices.supportsPosixPermissions());
        } catch (IOException e) {
            log.warn("Couldn't write {}", openSslConfigPath, e);
            throw new TorStartupFailedException("Couldn't write " + openSslConfigPath + ": " + e);
        }
    }

    private Map<String, String> createTorrcConfigFile(PasswordDigest hashedControlPassword, boolean isBundledTor) {
        TorrcClientConfigFactory torrcClientConfigFactory = TorrcClientConfigFactory.builder()
                .isTestNetwork(transportConfig.isTestNetwork())
                .dataDirPath(torDirectories.getDataDirPath())
                .hashedControlPassword(hashedControlPassword)
                .build();

        Map<String, String> torrcOverrideConfigs = transportConfig.getTorrcOverrides();
        Map<String, String> torrcConfigMap = torrcClientConfigFactory.torrcClientConfigMap(torrcOverrideConfigs);
        if (isBundledTor) {
            putBundledGeoIpFiles(torrcConfigMap, torDirectories);
        }

        var torrcFileGenerator = new TorrcFileGenerator(torDirectories.getTorrcPath(),
                torrcConfigMap,
                transportConfig.getDirectoryAuthorities());
        torrcFileGenerator.generate();
        return torrcConfigMap;
    }

    private static InetAddress getExternalTorBindAddress() {
        if (!LinuxDistribution.isWhonix()) {
            return LoopbackPorts.IPV4_LOOPBACK;
        }
        try {
            // The Tor of Whonix runs on the Whonix-Gateway and connects to the workstation over the internal network.
            return InetAddress.getByName("0.0.0.0");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }


    private static void closeQuietly(ServerSocket serverSocket) {
        try {
            serverSocket.close();
        } catch (IOException ignore) {
        }
    }
}
