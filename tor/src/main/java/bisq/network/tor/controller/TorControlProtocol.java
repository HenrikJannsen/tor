package bisq.network.tor.controller;

import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.events.listener.HsDescEventListener;
import bisq.network.tor.controller.exceptions.CannotConnectWithTorException;
import bisq.network.tor.controller.exceptions.CannotSendCommandToTorException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Sends commands to the control port of Tor and reads their replies. Tor answers the commands of a connection in
 * order, so each method which sends a command holds the lock of this object until it has read the reply. Otherwise a
 * thread could take the reply to the command of another thread. The methods which add or remove an event listener
 * hold the lock as well, from the change of the listeners until Tor has confirmed the SETEVENTS which follows from it:
 * otherwise two threads could send their SETEVENTS in the wrong order, and Tor would stop reporting the events which
 * a listener waits for. {@link #close()} does not take the lock, so that it can end a command which waits for its
 * reply.
 * <p>
 * A thread which is interrupted while it waits for a reply fails its command with a
 * {@link ControlCommandFailedException} and closes the connection, as a reply which does not arrive in time does: the
 * late reply would be taken as the reply to the next command. Every later command of this object fails, and Tor
 * removes the onion services which this connection added. A Tor whose ownership this connection took
 * ({@link #takeOwnership()}, which Bisq does for the Tor that it starts) exits then. Callers which interrupt a thread
 * that sends a command, for example on a shutdown, therefore end the use of this Tor.
 */
@Slf4j
public class TorControlProtocol implements AutoCloseable {
    private static final int MAX_CONNECTION_ATTEMPTS = 10;
    private static final String SERVICE_ID_REPLY_PREFIX = "250-ServiceID=";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int SAFE_COOKIE_NONCE_LENGTH = 32;
    private static final String SAFE_COOKIE_SERVER_TO_CONTROLLER_KEY =
            "Tor safe cookie authentication server-to-controller hash";
    private static final String SAFE_COOKIE_CONTROLLER_TO_SERVER_KEY =
            "Tor safe cookie authentication controller-to-server hash";
    // 250 AUTHCHALLENGE SERVERHASH=<64 hex digits> SERVERNONCE=<64 hex digits>
    private static final Pattern AUTHCHALLENGE_REPLY_PATTERN =
            Pattern.compile("^250 AUTHCHALLENGE SERVERHASH=([0-9A-Fa-f]{64}) SERVERNONCE=([0-9A-Fa-f]{64})$");
    // Far more than any reply to the commands of Bisq.
    static final int MAX_REPLY_LENGTH = 1024 * 1024;
    // The service ID of a v3 onion service: its address without ".onion"
    private static final Pattern SERVICE_ID_PATTERN = Pattern.compile("[a-z2-7]{56}");
    // Closes a connection whose write does not end in time. One daemon thread for all connections.
    private static final ScheduledThreadPoolExecutor WRITE_TIMEOUT_SCHEDULER = createWriteTimeoutScheduler();

    // Volatile like isClosed: close() sets the flag and then reads the socket, initialize sets the socket and then reads
    // the flag, so that one of them closes a socket which connects while the connection is closed.
    private volatile Socket controlSocket;
    private final TorControlReader torControlReader;
    private Optional<OutputStream> outputStream = Optional.empty();

    // MidReplyLine = StatusCode "-" ReplyLine
    // DataReplyLine = StatusCode "+" ReplyLine CmdData
    private final Pattern multiLineReplyPattern = Pattern.compile("^\\d+[-+].+");
    // CmdData = *DataLine "." CRLF. The data follows the DataReplyLine, until a line with a single dot.
    private static final Pattern DATA_REPLY_PATTERN = Pattern.compile("^\\d{3}\\+.*");
    private static final String DATA_END = ".";
    // Set by close() and never reset: a TorControlProtocol serves one connection.
    private volatile boolean isClosed;
    // The time in which Tor must send the whole reply to a command
    private final long replyTimeoutMs;

    public TorControlProtocol() {
        this(TorControlReader.REPLY_TIMEOUT_MS);
    }

    private static ScheduledThreadPoolExecutor createWriteTimeoutScheduler() {
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1, new ThreadFactoryBuilder()
                .setNameFormat("TorControlProtocol-write-timeout")
                .setDaemon(true)
                .build());
        // A write which ends in time cancels its timeout; the timeout must not stay queued for its whole delay.
        scheduler.setRemoveOnCancelPolicy(true);
        return scheduler;
    }

    TorControlProtocol(long replyTimeoutMs) {
        this.replyTimeoutMs = replyTimeoutMs;
        torControlReader = new TorControlReader();
    }

    public void initialize(int port) {
        try {
            Socket socket = createAndConnectControlSocket(port);
            controlSocket = socket;
            if (isClosed) {
                // close() ran while the socket connected and may not have seen it.
                closeQuietly(socket);
                throw closedWhileConnecting();
            }
            this.outputStream = Optional.of(socket.getOutputStream());
            this.torControlReader.start(socket.getInputStream());
            log.info("TorControlProtocol initialized successfully for port {}", port);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();  // Restore interrupted state
            log.error("TorControlProtocol initialization for port {} was interrupted.", port, e);
            close();
            throw new CannotConnectWithTorException(e);
        } catch (IOException e) {
            log.error("TorControlProtocol failed to set up streams for port {}.", port, e);
            close();
            throw new CannotConnectWithTorException(e);
        } catch (CannotConnectWithTorException e) {
            log.error("TorControlProtocol failed to connect to Tor control port {} (as thrown by createAndConnectControlSocket).", port, e);
            close();
            throw e;
        } catch (Exception e) {
            log.error("Unexpected exception during TorControlProtocol initialization for port {}.", port, e);
            close();
            throw new CannotConnectWithTorException(e);
        }
    }

    @Override
    public void close() {
        if (isClosed) {
            return;
        }
        isClosed = true;
        log.debug("Closing TorControlProtocol resources.");
        // The reader first, so that it takes the end of the stream which the closed socket causes as expected.
        try {
            torControlReader.close();
            log.debug("TorControlReader closed.");
        } catch (Exception e) {
            log.warn("Exception while closing TorControlReader.", e);
        }
        Socket socket = controlSocket;
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
                log.debug("Control socket closed.");
            }
        } catch (IOException e) {
            log.warn("IOException while closing control socket. This may be expected if connection was problematic.", e);
        }
        outputStream = Optional.empty();
    }

    public void authenticate(PasswordDigest passwordDigest) {
        byte[] secret = passwordDigest.getSecret();
        authenticate(BaseEncoding.base16().lowerCase().encode(secret));
    }

    public void authenticate(byte[] authCookie) {
        authenticate(BaseEncoding.base16().lowerCase().encode(authCookie));
    }

    /**
     * Authenticates with the plain password of the HashedControlPassword of Tor. The password is sent to the
     * process on the control port, which cannot prove that it is Tor.
     */
    public void authenticateWithPassword(String password) {
        authenticate(BaseEncoding.base16().lowerCase().encode(password.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Authenticates with the SAFECOOKIE method of the control protocol (control-spec, AUTHCHALLENGE). Unlike the
     * COOKIE method, it never sends the cookie: Tor first proves that it knows the cookie, so a process which only
     * listens on the control port gets neither the cookie nor the commands which follow.
     *
     * <p>
     * The method holds the lock for AUTHCHALLENGE and AUTHENTICATE, because Tor expects AUTHENTICATE as the next
     * command.
     *
     * @throws TorControlAuthenticationFailed if the process on the control port does not prove that it knows the
     *                                        cookie, or if it does not accept the authentication
     */
    public synchronized void authenticateWithSafeCookie(byte[] authCookie) {
        byte[] clientNonce = new byte[SAFE_COOKIE_NONCE_LENGTH];
        SECURE_RANDOM.nextBytes(clientNonce);
        sendCommand("AUTHCHALLENGE SAFECOOKIE " + BaseEncoding.base16().encode(clientNonce) + "\r\n");
        String reply = receiveReply().findFirst().orElseThrow();

        Matcher matcher = AUTHCHALLENGE_REPLY_PATTERN.matcher(reply);
        if (!matcher.matches()) {
            throw new TorControlAuthenticationFailed("Invalid reply to AUTHCHALLENGE: " + reply);
        }
        byte[] serverHash = BaseEncoding.base16().decode(matcher.group(1).toUpperCase(Locale.ROOT));
        byte[] serverNonce = BaseEncoding.base16().decode(matcher.group(2).toUpperCase(Locale.ROOT));

        byte[] expectedServerHash = safeCookieHash(SAFE_COOKIE_SERVER_TO_CONTROLLER_KEY, authCookie, clientNonce, serverNonce);
        if (!MessageDigest.isEqual(expectedServerHash, serverHash)) {
            // Nothing more may be sent to this process.
            close();
            throw new TorControlAuthenticationFailed("The process on the Tor control port does not know the " +
                    "authentication cookie. Another process may listen on the port.");
        }
        byte[] clientHash = safeCookieHash(SAFE_COOKIE_CONTROLLER_TO_SERVER_KEY, authCookie, clientNonce, serverNonce);
        authenticate(BaseEncoding.base16().lowerCase().encode(clientHash));
    }

    // HMAC-SHA256(key, CookieString | ClientNonce | ServerNonce)
    private static byte[] safeCookieHash(String key, byte[] authCookie, byte[] clientNonce, byte[] serverNonce) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            mac.update(authCookie);
            mac.update(clientNonce);
            mac.update(serverNonce);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private synchronized void authenticate(String secretAsHex) {
        String command = "AUTHENTICATE " + secretAsHex + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();

        // Tor answers "515 Authentication failed" to a wrong secret, but any reply other than "250 OK" means that
        // the connection is not authenticated, for example "514 Authentication required".
        if (!isSuccessReply(reply)) {
            throw new TorControlAuthenticationFailed(reply);
        }
    }

    /**
     * @return the service ID (the onion address without ".onion") which Tor reports for the key, if the reply
     * contains it
     */
    public synchronized Optional<String> addOnion(OnionServiceKey onionServiceKey, int onionPort, int localPort) {
        String base64SecretScalar = onionServiceKey.getBase64SecretScalar();
        String command = "ADD_ONION " + "ED25519-V3:" + base64SecretScalar + " Port=" + onionPort + "," + localPort + "\r\n";

        sendCommand(command);
        List<String> replies = receiveReply().collect(Collectors.toList());
        // ServiceID, and other lines for other forms of the command, such as PrivateKey. A filtering control port such
        // as onion-grater may leave the ServiceID out.
        List<String> serviceIds = getDataLinesOfSuccess(replies, "ADD_ONION").stream()
                .filter(line -> line.startsWith(SERVICE_ID_REPLY_PREFIX))
                .map(line -> line.substring(SERVICE_ID_REPLY_PREFIX.length()))
                .collect(Collectors.toList());
        if (serviceIds.size() > 1) {
            throw invalidReply("ADD_ONION", replies);
        }
        return serviceIds.stream().findFirst();
    }

    public synchronized void delOnion(String serviceId) {
        String command = "DEL_ONION " + serviceId + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't remove onion service " + serviceId + ": " + reply);
        }
    }

    /**
     * @return the reply line of the keyword, for example {@code 250-version=0.4.9.14}, or a data reply line with its
     * data, for example {@code 250+config-text=} and the lines of the configuration after line feeds
     */
    public synchronized String getInfo(String keyword) {
        String command = "GETINFO " + keyword + "\r\n";
        sendCommand(command);
        List<String> replies = receiveReply().collect(Collectors.toList());
        return getDataLinesOfSuccess(replies, "GETINFO").stream()
                .filter(line -> line.startsWith("250-" + keyword + "=") || line.startsWith("250+" + keyword + "="))
                .findFirst()
                .orElseThrow(() -> invalidReply("GETINFO", replies));
    }

    /**
     * @return the values of the configuration option {@code key}
     */
    public synchronized List<String> getConf(String key) {
        String command = "GETCONF " + key + "\r\n";
        sendCommand(command);
        List<String> replies = receiveReply().toList();
        Pattern valuePattern = Pattern.compile("^250[- ]" + Pattern.quote(key) + "=(.*)$", Pattern.CASE_INSENSITIVE);
        List<String> values = replies.stream()
                .map(valuePattern::matcher)
                .filter(Matcher::matches)
                .map(matcher -> matcher.group(1))
                .toList();
        if (values.isEmpty() || !replies.get(replies.size() - 1).startsWith("250 ")) {
            throw invalidReply("GETCONF", replies);
        }
        return values;
    }

    /**
     * @param serviceId the service ID of a v3 onion service (the address without ".onion"). The address of a peer
     *                  comes from the network, so the method accepts nothing else: a CR LF in the argument would
     *                  carry further commands into the control connection.
     * @throws IllegalArgumentException if the argument is not a service ID
     */
    public synchronized void hsFetch(String serviceId) {
        if (!SERVICE_ID_PATTERN.matcher(serviceId).matches()) {
            throw new IllegalArgumentException("The argument of HSFETCH is not the service ID of a v3 onion service");
        }
        String command = "HSFETCH " + serviceId + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            // The service ID is the address of a peer, so only at debug level: the apps log the exception, and a log
            // which a user shares must not name the peers of the user. The reply of Tor can name the address as well.
            log.debug("Couldn't initiate HSFETCH for {}: {}", serviceId, reply);
            throw new ControlCommandFailedException("Couldn't initiate HSFETCH");
        }
    }

    public synchronized void resetConf(String configName) {
        String command = "RESETCONF " + configName + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't reset config: " +
                    TorControlLogFormat.toLoggableOptionArgument(configName));
        }
    }

    public synchronized void setConfig(String configName, String configValue) {
        String command = "SETCONF " + configName + "=" + configValue + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            // The value can be a secret, and exception messages get logged
            throw new ControlCommandFailedException("Couldn't set config option: " + configName);
        }
    }

    public synchronized void takeOwnership() {
        String command = "TAKEOWNERSHIP\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't take ownership");
        }
    }

    /**
     * @param listener called once when the connection to the control port has ended, at once if it has ended already.
     *                 It is not called by {@link #close()} before the reader has noticed the closed socket. It runs on
     *                 the reader thread, with the rules of {@link TorControlReader}.
     */
    public void addConnectionEndListener(Runnable listener) {
        torControlReader.addConnectionEndListener(listener);
    }

    public void removeConnectionEndListener(Runnable listener) {
        torControlReader.removeConnectionEndListener(listener);
    }

    public synchronized void addBootstrapEventListener(BootstrapEventListener listener) {
        Set<String> previous = getEventTypesOfBootstrapEventListeners();
        torControlReader.addBootstrapEventListener(listener);
        String newEventType = listener.getEventType().name();
        if (!previous.contains(newEventType)) {
            refreshEventRegistration();
        } else {
            log.debug("We are already for that event registered");
        }
    }

    public synchronized void removeBootstrapEventListener(BootstrapEventListener listener) {
        Set<String> previous = getEventTypesOfBootstrapEventListeners();
        String newEventType = listener.getEventType().name();
        if (!previous.contains(newEventType)) {
            log.warn("Remove BootstrapEventListener but did not have eventType in listeners. This could happen if removeBootstrapEventListener was called without addBootstrapEventListener before.");
        }
        torControlReader.removeBootstrapEventListener(listener);
        Set<String> current = getEventTypesOfBootstrapEventListeners();
        if (!current.contains(newEventType)) {
            refreshEventRegistration();
        } else {
            log.debug("Event has been already removed from registration");
        }
    }

    private Set<String> getEventTypesOfBootstrapEventListeners() {
        return torControlReader.getBootstrapEventListeners().stream()
                .map(listener -> listener.getEventType().name())
                .collect(Collectors.toSet());
    }

    public synchronized void addHsDescEventListener(HsDescEventListener listener) {
        Set<String> previous = getEventTypesOfHsDescEventListeners();
        torControlReader.addHsDescEventListener(listener);
        String newEventType = listener.getEventType().name();
        if (!previous.contains(newEventType)) {
            refreshEventRegistration();
        } else {
            log.debug("We are already for that event registered");
        }
    }

    public synchronized void removeHsDescEventListener(HsDescEventListener listener) {
        Set<String> previous = getEventTypesOfHsDescEventListeners();
        String newEventType = listener.getEventType().name();
        if (!previous.contains(newEventType) && !isClosed) {
            log.warn("Remove HsDescEventListener but did not have eventType in listeners. This could happen if removeHsDescEventListener was called without addHsDescEventListener before.");
        }
        torControlReader.removeHsDescEventListener(listener);
        Set<String> current = getEventTypesOfHsDescEventListeners();
        if (!current.contains(newEventType)) {
            refreshEventRegistration();
        } else {
            log.debug("Event has been already removed from registration");
        }
    }

    private Set<String> getEventTypesOfHsDescEventListeners() {
        return torControlReader.getHsDescEventListeners().stream()
                .map(listener -> listener.getEventType().name())
                .collect(Collectors.toSet());
    }

    public synchronized void refreshEventRegistration() {
        registerEvents(eventTypesOfListeners());
    }

    /**
     * @return the event types of the registered listeners, which Tor must report (SETEVENTS)
     */
    Set<String> eventTypesOfListeners() {
        return Stream.concat(getEventTypesOfBootstrapEventListeners().stream(), getEventTypesOfHsDescEventListeners().stream())
                .collect(Collectors.toSet());
    }

    private synchronized void registerEvents(Set<String> events) {
        if (isClosed) {
            // Tor forgets the event registration with the connection. The services remove their listeners while the
            // controller shuts down, after the connection is closed.
            log.debug("The connection to the Tor control port is closed, SETEVENTS for {} is not sent", events);
            return;
        }
        if (events.isEmpty()) {
            log.info("Clear registered Events");
        } else {
            log.info("Register events {}", events);
        }
        var stringBuilder = new StringBuffer("SETEVENTS");
        events.forEach(event -> stringBuilder.append(" ").append(event));
        stringBuilder.append("\r\n");

        String command = stringBuilder.toString();
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't set events: " + events);
        }
    }

    private Socket createAndConnectControlSocket(int port) throws InterruptedException, CannotConnectWithTorException {
        int connectionAttempt = 0;
        Exception lastException = null;

        while (connectionAttempt < MAX_CONNECTION_ATTEMPTS) {
            // A close, for example by a shutdown during the start, ends the attempts.
            if (isClosed) {
                throw closedWhileConnecting();
            }
            Socket attemptSocket = new Socket();
            try {
                // The Tor Control Port communication is typically unencrypted. 
                // This is considered safe because the connection is made to 127.0.0.1 (localhost),
                // ensuring that the communication does not leave the local machine and is not 
                // exposed to external networks. Authentication (via cookie or password) 
                // is handled by the Tor control protocol itself after connection.
                var socketAddress = new InetSocketAddress("127.0.0.1", port);
                log.debug("Attempting to connect to Tor control port {} ({}/{})", socketAddress, connectionAttempt + 1, MAX_CONNECTION_ATTEMPTS);
                attemptSocket.connect(socketAddress);
                log.info("Successfully connected control socket to Tor port {} after {} attempts", port, connectionAttempt + 1);
                return attemptSocket;
            } catch (ConnectException e) {
                lastException = e;
                log.warn("ConnectException on attempt {} to Tor control port {}: {}. Closing attemptSocket.",
                        connectionAttempt + 1, port, e.getMessage());
                try {
                    attemptSocket.close();
                } catch (IOException closeEx) {
                    log.warn("Failed to close attemptSocket after ConnectException on port {}: {}", port, closeEx.getMessage(), closeEx);
                }
            } catch (IOException e) {
                lastException = e;
                log.warn("IOException on attempt {} to Tor control port {}: {}. Closing attemptSocket.",
                        connectionAttempt + 1, port, e.getMessage());
                try {
                    attemptSocket.close();
                } catch (IOException closeEx) {
                    log.warn("Failed to close attemptSocket after IOException on port {}: {}", port, closeEx.getMessage(), closeEx);
                }
            }

            connectionAttempt++;
            if (connectionAttempt < MAX_CONNECTION_ATTEMPTS) {
                log.debug("Connection attempt to Tor control port {} failed. Retrying in 200ms...", port);
                Thread.sleep(200);
            }
        }

        String errorMessage = "Failed to connect to Tor control port " + port + " after " + MAX_CONNECTION_ATTEMPTS + " attempts.";
        IOException wrapperException = new IOException(errorMessage, lastException);
        log.error(errorMessage, wrapperException);
        throw new CannotConnectWithTorException(wrapperException);
    }

    private static CannotConnectWithTorException closedWhileConnecting() {
        return new CannotConnectWithTorException("The connection to the Tor control port was closed while it was " +
                "being made");
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException e) {
            log.debug("Could not close the control socket", e);
        }
    }

    private void sendCommand(String command) {
        checkIsOneLine(command);
        if (isClosed) {
            throw new ControlCommandFailedException("The connection to the Tor control port is closed");
        }
        if (outputStream.isEmpty()) {
            throw new IllegalStateException("TorControlProtocol output stream not initialized. Cannot send command.");
        }
        // Debug level: the commands name onion addresses, which link the identities of a user in a shared log.
        log.debug("Send Tor control command: {}", TorControlLogFormat.toLoggableCommand(command));
        @SuppressWarnings("resource") OutputStream os = this.outputStream.orElseThrow();
        byte[] commandBytes = command.getBytes(StandardCharsets.US_ASCII);
        // A write blocks while Tor does not read, and it holds the lock of this object, which every command needs. A
        // socket has no timeout for writes, so the connection is closed if the write takes longer than a reply may.
        AtomicBoolean hasWriteTimedOut = new AtomicBoolean();
        ScheduledFuture<?> writeTimeout = WRITE_TIMEOUT_SCHEDULER.schedule(() -> {
            hasWriteTimedOut.set(true);
            close();
        }, replyTimeoutMs, TimeUnit.MILLISECONDS);
        try {
            os.write(commandBytes);
            os.flush();
        } catch (IOException e) {
            if (hasWriteTimedOut.get()) {
                throw new ControlCommandFailedException("Tor did not take the command within " + replyTimeoutMs +
                        " ms");
            }
            throw new CannotSendCommandToTorException(e);
        } finally {
            writeTimeout.cancel(false);
        }
    }

    /**
     * Every command of Bisq is one line which ends with CR LF. A CR, an LF or another control character inside the
     * line, for example in an argument which comes from the network or from a configuration, would end the command
     * early, and Tor would run the rest as further commands. The check covers every command, also those whose
     * arguments are trusted today.
     *
     * @throws IllegalArgumentException if the command is not one such line
     */
    private static void checkIsOneLine(String command) {
        boolean endsWithLineEnd = command.endsWith("\r\n");
        String line = endsWithLineEnd ? command.substring(0, command.length() - 2) : command;
        if (!endsWithLineEnd || line.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("A Tor control command must be one line without control characters");
        }
    }

    /**
     * @return the lines of the reply. A data reply line (for example "250+config-text=") carries the lines of its
     * data after a line feed, without the line with the single dot which ends the data.
     */
    private Stream<String> receiveReply() {
        var streamBuilder = Stream.<String>builder();
        int replyLength = 0;
        // One deadline for the whole reply: a Tor which sends one line at a time, each just before the timeout of
        // a line, must not hold the command forever. The monotonic clock, so that a change of the system time does
        // not shorten or extend it.
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(replyTimeoutMs);
        String reply;
        do {
            reply = tryReadNextReply(deadline);
            replyLength = addToReplyLength(replyLength, reply);
            if (isDataReply(reply)) {
                StringBuilder dataReply = new StringBuilder(reply);
                String dataLine;
                while (!(dataLine = readLineOfReply(deadline)).equals(DATA_END)) {
                    replyLength = addToReplyLength(replyLength, dataLine);
                    // A line of the data which starts with a dot is sent with a second dot in front.
                    dataReply.append('\n').append(dataLine.startsWith("..") ? dataLine.substring(1) : dataLine);
                }
                streamBuilder.add(dataReply.toString());
            } else {
                streamBuilder.add(reply);
            }
        } while (isMultilineReply(reply));

        return streamBuilder.build();
    }

    // Tor is not trusted. A reply without an end must not use unbounded memory. Every line counts with its line end,
    // so a reply of empty lines is bounded as well.
    private int addToReplyLength(int replyLength, String line) {
        int newReplyLength = replyLength + line.length() + 1;
        if (newReplyLength > MAX_REPLY_LENGTH) {
            close();
            throw new ControlCommandFailedException("Tor sent a reply longer than " + MAX_REPLY_LENGTH + " characters");
        }
        return newReplyLength;
    }

    private String tryReadNextReply(long deadline) {
        String reply = readLineOfReply(deadline);
        if (reply.equals("510 Command filtered")) {
            throw new TorCommandFilteredException();
        }
        return reply;
    }

    /**
     * @param deadline the value of {@link System#nanoTime()} until which the whole reply must have arrived
     */
    private String readLineOfReply(long deadline) {
        long remainingNanos = deadline - System.nanoTime();
        if (remainingNanos <= 0) {
            // A late line would be taken as the reply to the next command.
            close();
            throw new ControlCommandFailedException("Tor did not send the whole reply within " + replyTimeoutMs + " ms");
        }
        try {
            // Rounded up, so that less than a millisecond left still waits.
            return torControlReader.readLine(TimeUnit.NANOSECONDS.toMillis(remainingNanos) + 1);
        } catch (ControlCommandFailedException e) {
            // A late reply would be taken as the reply to the next command.
            close();
            throw e;
        }
    }

    private boolean isMultilineReply(String reply) {
        return multiLineReplyPattern.matcher(reply).matches();
    }

    private static boolean isDataReply(String reply) {
        return DATA_REPLY_PATTERN.matcher(reply).matches();
    }

    /**
     * A reply to a command which succeeded has mid or data reply lines with the status 250 and ends with "250 OK".
     * Anything else, also the reply to another command, which a broken or hostile Tor could send, fails the command.
     *
     * @return the lines before "250 OK"
     */
    private static List<String> getDataLinesOfSuccess(List<String> replies, String commandName) {
        boolean isSuccess = !replies.isEmpty() &&
                replies.get(replies.size() - 1).equals("250 OK") &&
                replies.stream().allMatch(line -> line.startsWith("250"));
        if (!isSuccess) {
            throw invalidReply(commandName, replies);
        }
        return replies.subList(0, replies.size() - 1);
    }

    private static ControlCommandFailedException invalidReply(String commandName, List<String> replies) {
        List<String> loggableReplies = replies.stream().map(TorControlLogFormat::toLoggableReply).collect(Collectors.toList());
        return new ControlCommandFailedException("Invalid " + commandName + " reply: " + loggableReplies);
    }

    private boolean isSuccessReply(String reply) {
        return reply.equals("250 OK");
    }
}
