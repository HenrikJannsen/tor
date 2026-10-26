package bisq.network.tor.controller;

import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.events.listener.HsDescEventListener;
import bisq.network.tor.controller.exceptions.CannotConnectWithTorException;
import bisq.network.tor.controller.exceptions.CannotSendCommandToTorException;
import bisq.network.tor.onionservice.OnionServiceKey;
import com.google.common.io.BaseEncoding;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
    // Closes a connection whose write does not end in time. One daemon thread for all connections.
    private static final ScheduledThreadPoolExecutor WRITE_TIMEOUT_SCHEDULER = createWriteTimeoutScheduler();

    private Socket controlSocket;
    private final TorControlReader torControlReader;
    private Optional<OutputStream> outputStream = Optional.empty();

    // MidReplyLine = StatusCode "-" ReplyLine
    // DataReplyLine = StatusCode "+" ReplyLine CmdData
    private final Pattern multiLineReplyPattern = Pattern.compile("^\\d+[-+].+");
    // CmdData = *DataLine "." CRLF. The data follows the DataReplyLine, until a line with a single dot.
    private static final Pattern DATA_REPLY_PATTERN = Pattern.compile("^\\d{3}\\+.*");
    private static final String DATA_END = ".";
    private volatile boolean closeInProgress;
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
            this.controlSocket = createAndConnectControlSocket(port);
            this.outputStream = Optional.of(this.controlSocket.getOutputStream());
            this.torControlReader.start(this.controlSocket.getInputStream());
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
        if (closeInProgress) {
            return;
        }
        closeInProgress = true;
        log.debug("Closing TorControlProtocol resources.");
        try {
            if (controlSocket != null && !controlSocket.isClosed()) {
                controlSocket.close();
                log.debug("Control socket closed.");
            }
        } catch (IOException e) {
            log.warn("IOException while closing control socket. This may be expected if connection was problematic.", e);
        }
        try {
            torControlReader.close();
            log.debug("TorControlReader closed.");
        } catch (Exception e) {
            log.warn("Exception while closing TorControlReader.", e);
        }
        outputStream = Optional.empty();
        closeInProgress = false;
    }

    public void authenticate(PasswordDigest passwordDigest) {
        byte[] secret = passwordDigest.getSecret();
        authenticate(BaseEncoding.base16().lowerCase().encode(secret));
    }

    public void authenticate(byte[] authCookie) {
        authenticate(BaseEncoding.base16().lowerCase().encode(authCookie));
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
        Stream<String> replyStream = receiveReply();
        String reply = validateReply(replyStream, "ADD_ONION");
        return reply.startsWith(SERVICE_ID_REPLY_PREFIX) ?
                Optional.of(reply.substring(SERVICE_ID_REPLY_PREFIX.length())) :
                Optional.empty();
    }

    public synchronized void delOnion(String serviceId) {
        String command = "DEL_ONION " + serviceId + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't remove onion service " + serviceId + ": " + reply);
        }
    }

    public synchronized String getInfo(String keyword) {
        String command = "GETINFO " + keyword + "\r\n";
        sendCommand(command);
        Stream<String> replyStream = receiveReply();
        return validateReply(replyStream, "GETINFO");
    }

    public synchronized void hsFetch(String hsAddress) {
        String command = "HSFETCH " + hsAddress + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't initiate HSFETCH for : " + hsAddress);
        }
    }

    public synchronized void resetConf(String configName) {
        String command = "RESETCONF " + configName + "\r\n";
        sendCommand(command);
        String reply = receiveReply().findFirst().orElseThrow();
        if (!isSuccessReply(reply)) {
            throw new ControlCommandFailedException("Couldn't reset config: " + configName);
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
        if (!previous.contains(newEventType) && !closeInProgress) {
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

    private void sendCommand(String command) {
        if (closeInProgress) {
            return;
        }
        if (outputStream.isEmpty()) {
            throw new IllegalStateException("TorControlProtocol output stream not initialized. Cannot send command.");
        }
        log.info("Send Tor control command: {}", TorControlLogFormat.toLoggableCommand(command));
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
     * @return the lines of the reply. A data reply line (for example "250+config-text=") carries the lines of its
     * data after a line feed, without the line with the single dot which ends the data.
     */
    private Stream<String> receiveReply() {
        var streamBuilder = Stream.<String>builder();
        // One deadline for the whole reply: a Tor which sends one line at a time, each just before the timeout of
        // a line, must not hold the command forever. The monotonic clock, so that a change of the system time does
        // not shorten or extend it.
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(replyTimeoutMs);
        String reply;
        do {
            reply = tryReadNextReply(deadline);
            if (isDataReply(reply)) {
                StringBuilder dataReply = new StringBuilder(reply);
                String dataLine;
                while (!(dataLine = readLineOfReply(deadline)).equals(DATA_END)) {
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

    // TODO check if this change is correct
    // We can receive 1 entry with "250 OK" or multiple entries starting with "250-" and the last entry with "250 OK"
    // Multiple entries following a single entry have been observed when using multiple user profiles.
    // E.g. [250 OK]
    // [250-ServiceID=bedb3wpuybkuwvjat2zq5odtqbajq7x3ovllvh7l2kbxakbgkzgikqyd, 250 OK]
    // [250-ServiceID=bedb3wpuybkuwvjat2zq5odtqbajq7x3ovllvh7l2kbxakbgkzgikqyd, 250-ServiceID=xjlwqzk6n4i5co574jrljsigelx6itzya32cfb7sfofqn7wueyhjj4id, 250 OK]
    private String validateReply(Stream<String> replyStream, String commandName) {
        List<String> replies = replyStream.collect(Collectors.toList());

        String OK250 = "250 OK";
        boolean hasOK250 = replies.stream().anyMatch(e -> e.equals(OK250));
        List<String> listOf250WithData = replies.stream()
                .filter(e -> e.startsWith("250-") || e.startsWith("250+"))
                .collect(Collectors.toList());
        if (!listOf250WithData.isEmpty()) {
            // TODO are there use cases where we need all 250WithData entries?
            return listOf250WithData.get(0);
        } else if (hasOK250) {
            return OK250;
        } else {
            List<String> loggableReplies = replies.stream().map(TorControlLogFormat::toLoggableReply).collect(Collectors.toList());
            throw new ControlCommandFailedException("Invalid " + commandName + " reply: " + loggableReplies);
        }

       /* if (replies.size() != 2) {
            throw new ControlCommandFailedException("Invalid " + commandName + " reply: " + replies);
        }

        String firstLine = replies.get(0);
        if (!firstLine.startsWith("250-")) {
            throw new ControlCommandFailedException("Invalid " + commandName + " reply: " + replies);
        }

        String secondLine = replies.get(1);
        if (!secondLine.equals("250 OK")) {
            throw new ControlCommandFailedException("Invalid " + commandName + " reply: " + replies);
        }

        return firstLine;*/
    }

    private boolean isSuccessReply(String reply) {
        return reply.equals("250 OK");
    }
}
