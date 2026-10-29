package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.EventType;
import bisq.network.tor.controller.events.events.HsDescEvent;
import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import bisq.network.tor.controller.events.listener.BootstrapEventListener;
import bisq.network.tor.controller.events.listener.HsDescEventListener;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * The listeners of events and of the end of the connection run on the thread of this reader, which also delivers the
 * replies to the commands. A listener must therefore return quickly and must not send a command or add or remove a
 * listener: {@link TorControlProtocol} sends a command under its lock and waits for the reply, which this thread cannot
 * deliver while it runs the listener. The command then fails after {@link #REPLY_TIMEOUT_MS}, and the connection is
 * closed. A listener hands such work to another thread.
 */
@Slf4j
public class TorControlReader implements AutoCloseable {
    // Tor answers the commands of Bisq at once. Slow operations, such as the upload of an onion service descriptor,
    // report their result later as events.
    static final long REPLY_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(60);
    private static final Pattern DATA_LINE_PATTERN = Pattern.compile("^\\d{3}\\+.*");
    // CmdData = *DataLine "." CRLF
    private static final String DATA_END = ".";

    // An empty element marks the end of the stream.
    private final BlockingQueue<Optional<String>> replies = new LinkedBlockingQueue<>();
    @Getter
    private final List<BootstrapEventListener> bootstrapEventListeners = new CopyOnWriteArrayList<>();
    @Getter
    private final List<HsDescEventListener> hsDescEventListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> connectionEndListeners = new CopyOnWriteArrayList<>();

    private Optional<Thread> workerThread = Optional.empty();
    private volatile boolean isStopped;
    private volatile boolean hasConnectionEnded;

    public void start(InputStream inputStream) {
        Thread thread = new Thread(() -> {
            Thread.currentThread().setName("TorControlReader.start");
            try {
                var bufferedReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.US_ASCII));

                String line;
                // The lines after a data reply line ("250+key=") or a data event line ("650+NAME") until the line
                // with the single dot are data (control-spec, CmdData). A data line belongs to the reply or the
                // event, whatever it starts with.
                boolean isInDataBlock = false;
                boolean isDataBlockOfEvent = false;
                while (!isStopped && (line = bufferedReader.readLine()) != null && !Thread.currentThread().isInterrupted()) {

                    log.info("Received reply from Tor control server: {}", TorControlLogFormat.toLoggableReply(line));
                    if (isInDataBlock) {
                        if (!isDataBlockOfEvent) {
                            replies.add(Optional.of(line));
                        }
                        isInDataBlock = !line.equals(DATA_END);
                    } else if (isEventWithCode_650(line)) {
                        handleEvent(line);
                        // Bisq registers no event with data, so the data of such an event belongs to no command.
                        isInDataBlock = isDataLine(line);
                        isDataBlockOfEvent = true;
                    } else {
                        replies.add(Optional.of(line));
                        isInDataBlock = isDataLine(line);
                        isDataBlockOfEvent = false;
                    }

                    if (Thread.interrupted()) {
                        break;
                    }
                }
            } catch (IOException e) {
                if (!isStopped) {
                    log.error("Tor control port reader couldn't read reply.", e);
                }
            } finally {
                // Wake up the callers waiting for a reply.
                replies.add(Optional.empty());
                // The flag first: a listener which is added from now on is notified by addConnectionEndListener.
                hasConnectionEnded = true;
                connectionEndListeners.forEach(TorControlReader::notifyConnectionEnd);
            }
        });
        workerThread = Optional.of(thread);
        thread.start();
    }

    private void handleEvent(String line) {
        String[] parts = line.split(" ");

        boolean parsedEvent = false;
        try {
            if (parts.length > 2) {
                String eventType = parts[1];

                if (isStatusClientEvent(eventType)) {
                    Optional<TorBootstrapEvent> bootstrapEventOptional = BootstrapEventParser.tryParse(parts);
                    if (bootstrapEventOptional.isPresent()) {
                        parsedEvent = true;
                        TorBootstrapEvent torBootstrapEvent = bootstrapEventOptional.get();
                        for (BootstrapEventListener listener : bootstrapEventListeners) {
                            notifyListener(() -> listener.onBootstrapStatusEvent(torBootstrapEvent), line);
                        }
                    }

                } else if (isHsDescEvent(eventType)) {
                    Optional<HsDescEvent> hsDescEventOptional = HsDescEventParser.tryParse(parts);
                    if (hsDescEventOptional.isPresent()) {
                        parsedEvent = true;
                        HsDescEvent hsDescEvent = hsDescEventOptional.get();
                        for (HsDescEventListener listener : hsDescEventListeners) {
                            notifyListener(() -> listener.onHsDescEvent(hsDescEvent), line);
                        }
                    }
                }
            }
        } catch (RuntimeException e) {
            // A malformed event must not end the reader. Otherwise every later command would wait forever.
            log.warn("Could not handle Tor event: {}", TorControlLogFormat.toLoggableReply(line), e);
            return;
        }

        if (!parsedEvent) {
            log.info("Unknown Tor event: {}", TorControlLogFormat.toLoggableReply(line));
        }
    }

    private static void notifyConnectionEnd(Runnable listener) {
        try {
            listener.run();
        } catch (RuntimeException e) {
            log.warn("A listener could not handle the end of the Tor control connection", e);
        }
    }

    // A listener which fails must not keep the event from the other listeners.
    private static void notifyListener(Runnable notification, String line) {
        try {
            notification.run();
        } catch (RuntimeException e) {
            log.warn("A listener could not handle the Tor event: {}", TorControlLogFormat.toLoggableReply(line), e);
        }
    }

    @Override
    public void close() {
        isStopped = true;
        workerThread.ifPresent(Thread::interrupt);
    }

    /**
     * @throws ControlCommandFailedException if the connection ended, if no reply arrived within the timeout, or if
     *                                       the thread was interrupted while it waited
     */
    public String readLine() {
        return readLine(REPLY_TIMEOUT_MS);
    }

    String readLine(long timeoutMs) {
        try {
            Optional<String> reply = replies.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (reply == null) {
                throw new ControlCommandFailedException("Tor did not reply within " + timeoutMs + " ms");
            }
            if (reply.isEmpty()) {
                // Leave the end marker for the other callers.
                replies.offer(reply);
                throw new ControlCommandFailedException("The connection to the Tor control port has ended");
            }
            return reply.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupted state
            // The reply may still arrive. The caller closes the connection on this exception, so that the reply is
            // not taken as the reply to the next command.
            throw new ControlCommandFailedException("The wait for the reply of Tor was interrupted", e);
        }
    }

    /**
     * Registers a listener which is called once the connection has ended, for example because Tor exited. A listener
     * which is added after the end is called at once; a listener which is added while the connection ends may be
     * called twice.
     */
    public void addConnectionEndListener(Runnable listener) {
        connectionEndListeners.add(listener);
        if (hasConnectionEnded) {
            notifyConnectionEnd(listener);
        }
    }

    public void removeConnectionEndListener(Runnable listener) {
        connectionEndListeners.remove(listener);
    }

    public void addBootstrapEventListener(BootstrapEventListener listener) {
        bootstrapEventListeners.add(listener);
    }

    public void removeBootstrapEventListener(BootstrapEventListener listener) {
        bootstrapEventListeners.remove(listener);
    }

    public void addHsDescEventListener(HsDescEventListener listener) {
        hsDescEventListeners.add(listener);
    }

    public void removeHsDescEventListener(HsDescEventListener listener) {
        hsDescEventListeners.remove(listener);
    }

    private boolean isEventWithCode_650(String line) {
        // 650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED
        return line.startsWith("650");
    }

    // DataReplyLine = StatusCode "+" ReplyLine CmdData, for example "250+config-text=" or "650+NEWCONSENSUS"
    private static boolean isDataLine(String line) {
        return DATA_LINE_PATTERN.matcher(line).matches();
    }

    private static boolean isStatusClientEvent(String eventType) {
        // 650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED
        return eventType.equals(EventType.STATUS_CLIENT.name());
    }

    private static boolean isHsDescEvent(String eventType) {
        // 650 HS_DESC CREATED <onion_address> UNKNOWN UNKNOWN <descriptor_id>
        return eventType.equals(EventType.HS_DESC.name());
    }
}
