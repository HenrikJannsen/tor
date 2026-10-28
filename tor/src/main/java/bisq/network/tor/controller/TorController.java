package bisq.network.tor.controller;

import bisq.network.tor.controller.exceptions.HsDescUploadFailedException;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.onionservice.OnionServiceKey;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class TorController {
    // For example 0.4.9.14 or 0.4.9.1-alpha
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\d+(?:\\.\\d+)+(?:-[0-9A-Za-z]+)?");
    private final TorControlProtocol torControlProtocol = new TorControlProtocol();
    private final int bootstrapTimeout; // in ms
    private final int hsUploadTimeout; // in ms
    private final long isOnlineTimeout = TimeUnit.SECONDS.toMillis(30); // in ms
    private final Map<String, PublishOnionAddressService> publishOnionAddressServiceMap = new ConcurrentHashMap<>();
    private final Map<String, OnionServiceOnlineStateService> onionServiceOnlineStateServiceMap = new ConcurrentHashMap<>();
    private Optional<BootstrapService> bootstrapService = Optional.empty();
    private volatile boolean isShutdownInProgress;

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
        isShutdownInProgress = true;
        // The connection first: a command which waits for the reply of a Tor that does not answer any more ends at
        // once, and the services send no SETEVENTS while they shut down, because Tor forgets the event registration
        // with the connection.
        runQuietly(torControlProtocol::close, "closing the connection to the Tor control port");
        bootstrapService.ifPresent(service -> runQuietly(service::shutdown, "the shutdown of the bootstrap"));
        bootstrapService = Optional.empty();
        publishOnionAddressServiceMap.values().forEach(service ->
                runQuietly(service::shutdown, "the shutdown of a publication"));
        publishOnionAddressServiceMap.clear();
        onionServiceOnlineStateServiceMap.values().forEach(service ->
                runQuietly(service::shutdown, "the shutdown of an onion service lookup"));
        onionServiceOnlineStateServiceMap.clear();
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
        if (bootstrapService.isPresent() && bootstrapService.get().getFuture().isPresent()) {
            return bootstrapService.get().getFuture().get();
        }

        BootstrapService service = new BootstrapService(torControlProtocol, bootstrapTimeout);
        bootstrapService = Optional.of(service);
        CompletableFuture<Void> future = service.bootstrap();
        future.whenComplete((nil, throwable) -> bootstrapService = Optional.empty());
        return future;
    }

    /**
     * @throws InterruptedException if the thread is interrupted while it waits. The publication goes on in the
     *                              background; a later call for the same onion address waits for it.
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
        String onionAddress = onionServiceKey.getOnionAddress();
        if (publishOnionAddressServiceMap.containsKey(onionAddress) && publishOnionAddressServiceMap.get(onionAddress).getFuture().isPresent()) {
            return publishOnionAddressServiceMap.get(onionAddress).getFuture().get();
        }

        PublishOnionAddressService publishOnionAddressService = new PublishOnionAddressService(torControlProtocol, hsUploadTimeout, onionServiceKey);
        CompletableFuture<Void> future = publishOnionAddressService.publish(onionServicePort, localPort);
        future.whenComplete((nil, throwable) -> publishOnionAddressServiceMap.remove(onionAddress));
        publishOnionAddressServiceMap.put(onionAddress, publishOnionAddressService);
        return future;
    }

    public CompletableFuture<Boolean> isOnionServiceOnlineAsync(String onionAddress) {
        if (isShutdownInProgress) {
            return CompletableFuture.completedFuture(false);
        }
        if (onionServiceOnlineStateServiceMap.containsKey(onionAddress) && onionServiceOnlineStateServiceMap.get(onionAddress).getFuture().isPresent()) {
            return onionServiceOnlineStateServiceMap.get(onionAddress).getFuture().get();
        }

        OnionServiceOnlineStateService onionServiceOnlineStateService = new OnionServiceOnlineStateService(torControlProtocol, onionAddress, isOnlineTimeout);
        CompletableFuture<Boolean> future = onionServiceOnlineStateService.isOnionServiceOnlineAsync();
        future.whenComplete((r, t) -> onionServiceOnlineStateServiceMap.remove(onionAddress));
        onionServiceOnlineStateServiceMap.put(onionAddress, onionServiceOnlineStateService);
        return future;
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
        String socksListenersString = torControlProtocol.getInfo("net/listeners/socks");
        String socksListener;
        if (socksListenersString.contains(" ")) {
            String[] socksPorts = socksListenersString.split(" ");
            socksListener = socksPorts[0];
        } else {
            socksListener = socksListenersString;
        }

        // "127.0.0.1:12345"
        socksListener = socksListener.replace("\"", "");
        String portString = socksListener.split(":")[1];
        return Integer.parseInt(portString);
    }
}
