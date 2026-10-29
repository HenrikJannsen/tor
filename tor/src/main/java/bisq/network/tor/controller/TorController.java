package bisq.network.tor.controller;

import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.annotations.VisibleForTesting;
import lombok.extern.slf4j.Slf4j;

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

@Slf4j
public class TorController {
    private static final String SOCKS_LISTENERS_KEY = "net/listeners/socks";
    // For example 0.4.9.14 or 0.4.9.1-alpha
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d+(?:\\.\\d+)+(?:-[0-9A-Za-z]+)?");
    // A QuotedString of the control protocol, which escapes a quote and a backslash with a backslash
    private static final Pattern QUOTED_STRING = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
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
        this.bootstrapTimeout = bootstrapTimeout;
        this.hsUploadTimeout = hsUploadTimeout;
    }

    public void initialize(int controlPort) {
        torControlProtocol.initialize(controlPort);
    }

    public void authenticate(byte[] authCookie) {
        torControlProtocol.authenticate(authCookie);
    }

    public void authenticate() {
        // No authentication required, but we still need to send an empty
        // AUTHENTICATE call to be able to send control commands
        torControlProtocol.authenticate(new byte[0]);
    }

    public void authenticate(PasswordDigest hashedControlPassword) {
        torControlProtocol.authenticate(hashedControlPassword);
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
     * @param socksListenersReply the reply line of GETINFO net/listeners/socks, for example
     *                            {@code 250-net/listeners/socks="unix:/run/tor/socks" "127.0.0.1:9050"}
     * @return the port of the first TCP listener. The system Tor of Debian lists its Unix socket first.
     */
    static int parseSocksPort(String socksListenersReply) {
        String prefix = "250-" + SOCKS_LISTENERS_KEY + "=";
        if (!socksListenersReply.startsWith(prefix)) {
            throw new ControlCommandFailedException("Invalid reply to GETINFO " + SOCKS_LISTENERS_KEY + ": " +
                    socksListenersReply);
        }
        Matcher listenerMatcher = QUOTED_STRING.matcher(socksListenersReply.substring(prefix.length()));
        while (listenerMatcher.find()) {
            String listener = listenerMatcher.group(1);
            int portSeparator = listener.lastIndexOf(':');
            if (!listener.startsWith("unix:") && portSeparator >= 0) {
                try {
                    return Integer.parseInt(listener.substring(portSeparator + 1));
                } catch (NumberFormatException ignore) {
                    // Not a TCP listener
                }
            }
        }
        throw new ControlCommandFailedException("Tor has no TCP SOCKS listener: " + socksListenersReply);
    }
}
