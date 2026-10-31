package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.TorBootstrapEvent;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BootstrapEventParserTest {
    private static final String BRIDGE_FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567";
    private static final String BRIDGE_ADDRESS = "192.0.2.77:44321";

    @Test
    void parsesTheSummaryOfAProgressEvent() {
        TorBootstrapEvent event = parse("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors " +
                "SUMMARY=\"Loading relay descriptors\"").orElseThrow();

        assertThat(event.getProgress()).isEqualTo(50);
        assertThat(event.getTag()).isEqualTo("loading_descriptors");
        assertThat(event.getSummary()).isEqualTo("Loading relay descriptors");
    }

    @Test
    void parsesTheDoneEvent() {
        TorBootstrapEvent event = parse("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"")
                .orElseThrow();

        assertThat(event.isDoneEvent()).isTrue();
        assertThat(event.getSummary()).isEqualTo("Done");
    }

    // The event as Tor 0.4.9 sends it when it cannot connect to a bridge
    @Test
    void theEventOfAWarningNamesNoBridge() {
        TorBootstrapEvent event = parse("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=5 TAG=conn " +
                "SUMMARY=\"Connecting to a relay\" WARNING=\"Connection refused\" REASON=CONNECTREFUSED COUNT=3 " +
                "RECOMMENDATION=warn HOSTID=\"" + BRIDGE_FINGERPRINT + "\" HOSTADDR=\"" + BRIDGE_ADDRESS + "\"")
                .orElseThrow();

        // The summary keeps what went wrong
        assertThat(event.getSummary()).isEqualTo("Connecting to a relay (Connection refused, CONNECTREFUSED)");
        // The bootstrap service logs the event
        assertThat(event.toString())
                .doesNotContain(BRIDGE_FINGERPRINT)
                .doesNotContain(BRIDGE_ADDRESS);
    }

    // A value without its closing quote does not take the arguments after it
    @Test
    void aWarningWithoutItsClosingQuoteNamesNoBridge() {
        TorBootstrapEvent event = parse("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=5 TAG=conn " +
                "SUMMARY=\"Connecting to a relay\" WARNING=\"Connection refused REASON=CONNECTREFUSED HOSTID=" +
                BRIDGE_FINGERPRINT + " HOSTADDR=" + BRIDGE_ADDRESS).orElseThrow();

        assertThat(event.toString())
                .doesNotContain(BRIDGE_FINGERPRINT)
                .doesNotContain(BRIDGE_ADDRESS);
    }

    // TorControlReader logs only the class of the exception of a malformed event
    @Test
    void anEventWithoutSummaryIsMalformed() {
        assertThatThrownBy(() -> parse("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=5 TAG=conn " +
                "HOSTID=\"" + BRIDGE_FINGERPRINT + "\" HOSTADDR=\"" + BRIDGE_ADDRESS + "\""))
                .isInstanceOf(IllegalArgumentException.class)
                .message()
                .doesNotContain(BRIDGE_FINGERPRINT)
                .doesNotContain(BRIDGE_ADDRESS);
    }

    @Test
    void ignoresOtherStatusEvents() {
        assertThat(parse("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED A B C")).isEmpty();
    }

    // As TorControlReader splits an event line
    private static Optional<TorBootstrapEvent> parse(String line) {
        return BootstrapEventParser.tryParse(line.split(" "));
    }
}
