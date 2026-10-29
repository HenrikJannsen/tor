package bisq.network.tor.controller;

import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.annotations.VisibleForTesting;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
public class TorController {
    private static final String SOCKS_LISTENERS_KEY = "net/listeners/socks";
    private static final String SOCKS_PORT_KEY = "SocksPort";
    private static final String HIDDEN_SOCKS_PORT_KEY = "__SocksPort";
    private static final String BOOTSTRAP_PHASE_KEY = "status/bootstrap-phase";
    private static final long BOOTSTRAP_POLL_INTERVAL_MS = 1000;
    // For example 0.4.9.14 or 0.4.9.1-alpha
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d+(?:\\.\\d+)+(?:-[0-9A-Za-z]+)?");
    // A QuotedString of the control protocol, which escapes a quote and a backslash with a backslash
    private static final Pattern QUOTED_STRING = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
    private final TorControlProtocol torControlProtocol;
    private final int bootstrapTimeout; // in ms
    private final int hsUploadTimeout; // in ms
    private final long isOnlineTimeout = TimeUnit.SECONDS.toMillis(30); // in ms
    // The running operations per onion address, and the publications which succeeded on this connection
    private final Map<String, Operation<Void>> publications = new ConcurrentHashMap<>();
    private final Map<String, Operation<Boolean>> onlineChecks = new ConcurrentHashMap<>();
    // Written by the thread which bootstraps, and by the shutdown, which runs on another thread
    private volatile Optional<BootstrapService> bootstrapService = Optional.empty();
    private volatile boolean isShutdownInProgress;

    /**
     * A publication or an online check of one onion address, with the shutdown of its service and its result.
     */
    @VisibleForTesting
    record Operation<T>(Runnable shutdown, CompletableFuture<T> result) {
    }

    public TorController(int bootstrapTimeout, int hsUploadTimeout) {
        this(bootstrapTimeout, hsUploadTimeout, new TorControlProtocol());
    }

    /**
     * @param isWhonix Bisq runs on a Whonix-Workstation, whose Gateway filters the control port with onion-grater
     */
    public TorController(int bootstrapTimeout, int hsUploadTimeout, boolean isWhonix) {
        this(bootstrapTimeout, hsUploadTimeout, new TorControlProtocol(isWhonix));
    }

    private TorController(int bootstrapTimeout, int hsUploadTimeout, TorControlProtocol torControlProtocol) {
        this.bootstrapTimeout = bootstrapTimeout;
        this.hsUploadTimeout = hsUploadTimeout;
        this.torControlProtocol = torControlProtocol;
    }

    public void initialize(int controlPort) {
        torControlProtocol.initialize(controlPort);
    }

    public void initialize(String controlHost, int controlPort) {
        torControlProtocol.initialize(controlHost, controlPort);
    }

    public void authenticate(byte[] authCookie) {
        torControlProtocol.authenticate(authCookie);
    }

    public void authenticateWithSafeCookie(byte[] authCookie) {
        torControlProtocol.authenticateWithSafeCookie(authCookie);
    }

    public void authenticateWithPassword(String password) {
        torControlProtocol.authenticateWithPassword(password);
    }

    public void authenticate() {
        // No authentication required, but we still need to send an empty
        // AUTHENTICATE call to be able to send control commands
        torControlProtocol.authenticate(new byte[0]);
    }

    public void authenticate(PasswordDigest hashedControlPassword) {
        torControlProtocol.authenticate(hashedControlPassword);
    }

    /**
     * Checks that the process on the control port uses the torrc which Bisq wrote for this start. It reports the
     * salted hash of the control password from that torrc. Another process which listens on the port (for example
     * after it took the port before Tor could bind it) accepts any password, but cannot know the salted hash,
     * because the torrc is readable only by the user.
     */
    public void verifyHashedControlPassword(PasswordDigest hashedControlPassword) {
        List<String> values = torControlProtocol.getConf("HashedControlPassword");
        boolean isExpected = values.size() == 1 &&
                values.get(0).equalsIgnoreCase(hashedControlPassword.getHashedPassword());
        if (!isExpected) {
            throw new TorControlAuthenticationFailed("The process on the Tor control port does not use the torrc of " +
                    "this start. Another process may listen on the port.");
        }
    }

    public void shutdown() {
        if (isShutdownInProgress) {
            return;
        }
        // Before the connection closes: a service which the end of the connection wakes up reports the shutdown.
        isShutdownInProgress = true;
        // The connection first: a command which waits for the reply of a Tor that does not answer any more ends at
        // once, and the services send no SETEVENTS while they shut down, because Tor forgets the event registration
        // with the connection.
        runQuietly(torControlProtocol::close, "closing the connection to the Tor control port");
        bootstrapService.ifPresent(service -> runQuietly(service::shutdown, "the shutdown of the bootstrap"));
        bootstrapService = Optional.empty();
        publications.values().forEach(operation ->
                runQuietly(operation.shutdown(), "the shutdown of a publication"));
        publications.clear();
        onlineChecks.values().forEach(operation ->
                runQuietly(operation.shutdown(), "the shutdown of an onion service lookup"));
        onlineChecks.clear();
    }

    private boolean isShutdownInProgress() {
        return isShutdownInProgress;
    }

    // One failing step must not keep the other steps of the shutdown from running.
    private static void runQuietly(Runnable step, String description) {
        try {
            step.run();
        } catch (RuntimeException e) {
            log.warn("Error at {} during the shutdown of the Tor controller", description, e);
        }
    }

    /**
     * @throws TorBootstrapFailedException if Tor did not bootstrap, also if the controller was shut down
     */
    public void bootstrap() {
        if (isShutdownInProgress) {
            // The caller must not take Tor as bootstrapped. A shutdown during the wait fails the same way.
            throw new TorBootstrapFailedException("The Tor controller was shut down");
        }
        try {
            bootstrapAsync().get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TorBootstrapFailedException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof TorBootstrapFailedException) {
                throw (TorBootstrapFailedException) cause;
            }
            log.error("Error at bootstrap", cause);
            throw new TorBootstrapFailedException(cause);
        }
    }

    public CompletableFuture<Void> bootstrapAsync() {
        // One read: the shutdown can clear the field meanwhile.
        Optional<CompletableFuture<Void>> runningBootstrap = bootstrapService.flatMap(BootstrapService::getFuture);
        if (runningBootstrap.isPresent()) {
            return runningBootstrap.get();
        }

        BootstrapService service = new BootstrapService(torControlProtocol, bootstrapTimeout, this::isShutdownInProgress);
        bootstrapService = Optional.of(service);
        CompletableFuture<Void> future = service.bootstrap();
        future.whenComplete((nil, throwable) -> bootstrapService = Optional.empty());
        return future;
    }

    /**
     * Waits until a Tor which Bisq did not start has bootstrapped, as netlayer did. Unlike {@link #bootstrap()}, it
     * does not change the configuration of that Tor: it asks Tor for its bootstrap phase once per second.
     *
     * @throws TorBootstrapFailedException if Tor has not bootstrapped within the bootstrap timeout
     */
    public void awaitBootstrapOfExternalTor() {
        long deadline = System.currentTimeMillis() + bootstrapTimeout;
        try {
            String bootstrapPhase = torControlProtocol.getInfo(BOOTSTRAP_PHASE_KEY);
            while (!isBootstrapDone(bootstrapPhase)) {
                if (isShutdownInProgress) {
                    throw new TorBootstrapFailedException("The Tor controller was shut down");
                }
                if (System.currentTimeMillis() >= deadline) {
                    throw new TorBootstrapFailedException("The external Tor did not bootstrap within " +
                            bootstrapTimeout / 1000 + " seconds. Its last state: " + bootstrapPhase);
                }
                Thread.sleep(BOOTSTRAP_POLL_INTERVAL_MS);
                bootstrapPhase = torControlProtocol.getInfo(BOOTSTRAP_PHASE_KEY);
            }
        } catch (TorCommandFilteredException e) {
            // A filtering proxy of the control port, such as onion-grater on Whonix, may refuse the request.
            log.info("The control port does not report the bootstrap phase of the external Tor, so Bisq does not wait " +
                    "for its bootstrap.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TorBootstrapFailedException(e);
        }
    }

    // 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
    static boolean isBootstrapDone(String bootstrapPhaseReply) {
        return bootstrapPhaseReply.contains(" PROGRESS=100 ");
    }

    /**
     * Publishes the onion service once per connection: a call for an onion address which is being published waits for
     * that publication, and a call after its success returns at once, because Tor keeps the onion service until the
     * connection ends. A call after a failure publishes anew.
     *
     * @throws InterruptedException if the thread is interrupted while it waits. The publication goes on in the
     *                              background, and a later call for the same onion address gets its result.
     * @throws CompletionException  with the cause of a failed publication, such as HsDescUploadFailedException
     */
    public void publish(OnionServiceKey onionServiceKey, int onionServicePort, int localPort) throws InterruptedException {
        if (isShutdownInProgress) {
            // The caller must not take the onion service as published.
            throw new HsDescUploadFailedException("The Tor controller is shut down");
        }
        try {
            publishAsync(onionServiceKey, onionServicePort, localPort).get();
        } catch (ExecutionException e) {
            throw new CompletionException(e.getCause());
        }
    }

    public CompletableFuture<Void> publishAsync(OnionServiceKey onionServiceKey,
                                                int onionServicePort,
                                                int localPort) {
        PublishOnionAddressService service = new PublishOnionAddressService(torControlProtocol, hsUploadTimeout,
                onionServiceKey, this::isShutdownInProgress);
        return runOnce(publications, onionServiceKey.getOnionAddress(), true, service::shutdown,
                () -> service.publish(onionServicePort, localPort));
    }

    /**
     * @param onionAddress a v3 onion address in any case, as Bisq 2 accepts it. Tor reads it in any case, but names it
     *                     in lower case in its events, so the lookup uses the lower case form.
     */
    public CompletableFuture<Boolean> isOnionServiceOnlineAsync(String onionAddress) {
        if (isShutdownInProgress) {
            return CompletableFuture.completedFuture(false);
        }
        String lowerCaseOnionAddress = onionAddress.toLowerCase(Locale.ROOT);
        OnionServiceOnlineStateService service = new OnionServiceOnlineStateService(torControlProtocol,
                lowerCaseOnionAddress, isOnlineTimeout, this::isShutdownInProgress);
        return runOnce(onlineChecks, lowerCaseOnionAddress, false, service::shutdown, service::isOnionServiceOnlineAsync);
    }

    /**
     * Starts an operation for the onion address, unless one runs for it already, whose result the caller gets then.
     * The operation is in the map before its work starts, so that a concurrent call finds it. It leaves the map before
     * its result is visible, so that a call which follows the result starts a new operation, and it removes only
     * itself.
     *
     * @param isSuccessKept whether a successful operation stays in the map, so that every later call gets its result
     */
    @VisibleForTesting
    static <T> CompletableFuture<T> runOnce(Map<String, Operation<T>> operations,
                                           String onionAddress,
                                           boolean isSuccessKept,
                                           Runnable shutdown,
                                           Supplier<CompletableFuture<T>> work) {
        Operation<T> operation = new Operation<>(shutdown, new CompletableFuture<>());
        Operation<T> runningOperation = operations.putIfAbsent(onionAddress, operation);
        if (runningOperation != null) {
            return runningOperation.result();
        }
        CompletableFuture<T> workResult;
        try {
            workResult = work.get();
        } catch (RuntimeException e) {
            workResult = CompletableFuture.failedFuture(e);
        }
        workResult.whenComplete((value, throwable) -> {
            if (throwable != null || !isSuccessKept) {
                operations.remove(onionAddress, operation);
            }
            if (throwable != null) {
                operation.result().completeExceptionally(throwable);
            } else {
                operation.result().complete(value);
            }
        });
        return operation.result();
    }

    /**
     * @return the version of the Tor on the control port, for example "0.4.9.14", or empty if the control port does
     * not report it
     */
    public Optional<String> getTorVersion() {
        try {
            // 250-version=0.4.9.14 (git-...). The control-spec allows a name before the version, such as "Tor".
            String reply = torControlProtocol.getInfo("version");
            String prefix = "250-version=";
            if (!reply.startsWith(prefix)) {
                return Optional.empty();
            }
            Matcher matcher = VERSION_PATTERN.matcher(reply.substring(prefix.length()));
            return matcher.find() ? Optional.of(matcher.group()) : Optional.empty();
        } catch (TorCommandFilteredException | ControlCommandFailedException e) {
            // A filtering proxy of the control port, such as onion-grater on Whonix, may refuse the request.
            return Optional.empty();
        }
    }

    public int getSocksPort() {
        String socksListenersReply = torControlProtocol.getInfo(SOCKS_LISTENERS_KEY);
        return parseSocksPort(socksListenersReply);
    }

    /**
     * Tor puts streams with different SOCKS credentials on different circuits only on a SOCKS port with the flag
     * IsolateSOCKSAuth, which it sets unless the configuration turns it off with NoIsolateSOCKSAuth. The listener of a
     * port {@code auto} gets its port when Tor opens it, so such an entry may be the one of the listener.
     *
     * @return the entries of SocksPort and __SocksPort which may have opened the SOCKS listener on {@code socksPort}
     * and turn the isolation by SOCKS credentials off, or empty if the control port does not report them, for example
     * because a filter in front of Tor refuses GETCONF, as onion-grater on Whonix does
     */
    public Optional<List<String>> findSocksPortsWithoutSocksAuthIsolation(int socksPort) {
        try {
            List<String> entries = new ArrayList<>(torControlProtocol.getConf(SOCKS_PORT_KEY));
            entries.addAll(torControlProtocol.getConf(HIDDEN_SOCKS_PORT_KEY));
            return Optional.of(entries.stream()
                    .filter(entry -> mayHaveOpenedListenerOn(entry, socksPort))
                    .filter(entry -> !isolatesBySocksAuthentication(entry))
                    .collect(Collectors.toList()));
        } catch (TorCommandFilteredException | ControlCommandFailedException e) {
            return Optional.empty();
        }
    }

    // A SocksPort entry is [address:]port, auto, unix:path or 0, followed by flags.
    @VisibleForTesting
    static boolean mayHaveOpenedListenerOn(String socksPortEntry, int socksPort) {
        String listener = socksPortEntry.trim().split("\\s+")[0];
        if (listener.startsWith("unix:")) {
            return false;
        }
        String port = listener.substring(listener.lastIndexOf(':') + 1);
        if (port.equalsIgnoreCase("auto")) {
            return true;
        }
        try {
            return Integer.parseInt(port) == socksPort;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // Tor reads the flags in any case, and the last of IsolateSOCKSAuth and NoIsolateSOCKSAuth counts.
    @VisibleForTesting
    static boolean isolatesBySocksAuthentication(String socksPortEntry) {
        boolean isIsolated = true;
        String[] fields = socksPortEntry.trim().split("\\s+");
        for (int i = 1; i < fields.length; i++) {
            if (fields[i].equalsIgnoreCase("IsolateSOCKSAuth")) {
                isIsolated = true;
            } else if (fields[i].equalsIgnoreCase("NoIsolateSOCKSAuth")) {
                isIsolated = false;
            }
        }
        return isIsolated;
    }

    /**
     * A TCP listener of the SOCKS port of Tor, with the address as Tor reports it, an IPv6 address without brackets
     */
    public record SocksListener(String address, int port) {
    }

    /**
     * @return the TCP listeners of the SOCKS port, in the order which Tor reports
     */
    public List<SocksListener> getSocksListeners() {
        return parseSocksListeners(torControlProtocol.getInfo(SOCKS_LISTENERS_KEY));
    }

    /**
     * @param socksListenersReply the reply line of GETINFO net/listeners/socks, for example
     *                            {@code 250-net/listeners/socks="unix:/run/tor/socks" "127.0.0.1:9050"}
     * @return the TCP listeners. The system Tor of Debian lists its Unix socket first.
     */
    static List<SocksListener> parseSocksListeners(String socksListenersReply) {
        String prefix = "250-" + SOCKS_LISTENERS_KEY + "=";
        if (!socksListenersReply.startsWith(prefix)) {
            throw new ControlCommandFailedException("Invalid reply to GETINFO " + SOCKS_LISTENERS_KEY + ": " +
                    socksListenersReply);
        }
        List<SocksListener> listeners = new ArrayList<>();
        Matcher listenerMatcher = QUOTED_STRING.matcher(socksListenersReply.substring(prefix.length()));
        while (listenerMatcher.find()) {
            String listener = listenerMatcher.group(1);
            int portSeparator = listener.lastIndexOf(':');
            if (!listener.startsWith("unix:") && portSeparator >= 0) {
                try {
                    int port = Integer.parseInt(listener.substring(portSeparator + 1));
                    String address = listener.substring(0, portSeparator);
                    boolean isInBrackets = address.startsWith("[") && address.endsWith("]");
                    listeners.add(new SocksListener(isInBrackets ? address.substring(1, address.length() - 1) : address,
                            port));
                } catch (NumberFormatException ignore) {
                    // Not a TCP listener
                }
            }
        }
        return listeners;
    }

    /**
     * @return the port of the first TCP listener
     */
    static int parseSocksPort(String socksListenersReply) {
        return parseSocksListeners(socksListenersReply).stream()
                .findFirst()
                .map(SocksListener::port)
                .orElseThrow(() -> new ControlCommandFailedException("Tor has no TCP SOCKS listener: " +
                        socksListenersReply));
    }
}
