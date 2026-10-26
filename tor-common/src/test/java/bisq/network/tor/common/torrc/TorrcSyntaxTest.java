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

package bisq.network.tor.common.torrc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorrcSyntaxTest {
    @Test
    void aValueWhichTorReadsWholeStaysAsItIs() {
        assertThat(TorrcSyntax.toValue("/home/user/.local/share/Bisq2/tor/data"))
                .isEqualTo("/home/user/.local/share/Bisq2/tor/data");
        assertThat(TorrcSyntax.toValue("C:\\Users\\Bob\\AppData\\Roaming\\Bisq2\\tor"))
                .isEqualTo("C:\\Users\\Bob\\AppData\\Roaming\\Bisq2\\tor");
    }

    // An unquoted value ends at "#", which starts a comment.
    @ParameterizedTest
    @ValueSource(strings = {"/home/user/Bisq#1/tor/data", "C:\\Users\\B\"ob\\#1\\tor", "/ends/with\\", " leading",
            "trailing ", "\"starts with a quote"})
    void aValueWhichTorWouldNotReadWholeIsQuoted(String value) {
        String torrcValue = TorrcSyntax.toValue(value);

        assertThat(torrcValue).startsWith("\"").endsWith("\"");
        assertThat(TorrcSyntax.findValueProblem(torrcValue)).isEmpty();
        assertThat(TorrcSyntax.decodeQuotedString(torrcValue)).isEqualTo(value);
    }

    @Test
    void aControlCharacterIsStillRefused() {
        assertThat(TorrcSyntax.findValueProblem(TorrcSyntax.toValue("/home/user/Bisq#1\n"))).isPresent();
    }

    @Test
    void anOptionNameHasLettersAndDigits() {
        assertThat(TorrcSyntax.isOptionName("ControlPort")).isTrue();
        assertThat(TorrcSyntax.isOptionName("Socks5Proxy")).isTrue();
        assertThat(TorrcSyntax.isOptionName("__OwningControllerProcess")).isTrue();
        assertThat(TorrcSyntax.isOptionName("controlport")).isTrue();
    }

    @Test
    void theTorrcFormsWhichChangeAnOptionAreNoOptionNames() {
        // Tor reads "+Key" as an addition to a list option, "/Key" as its removal and "Key#x" as the key "Key" with a
        // comment, and "%include" reads another file.
        assertThat(TorrcSyntax.isOptionName("+ControlPort")).isFalse();
        assertThat(TorrcSyntax.isOptionName("/ControlPort")).isFalse();
        assertThat(TorrcSyntax.isOptionName("ControlPort#x")).isFalse();
        assertThat(TorrcSyntax.isOptionName("%include")).isFalse();
        assertThat(TorrcSyntax.isOptionName("___Hidden")).isFalse();
        assertThat(TorrcSyntax.isOptionName("Control Port")).isFalse();
        assertThat(TorrcSyntax.isOptionName("")).isFalse();
    }

    @Test
    void aValueWhichTorWouldNotReadAsOneEntryHasAProblem() {
        assertThat(TorrcSyntax.findValueProblem("notice stdout")).isEmpty();
        assertThat(TorrcSyntax.findValueProblem("abc\tdef")).isEmpty();
        assertThat(TorrcSyntax.findValueProblem("\"abc#def\"")).isEmpty();
        assertThat(TorrcSyntax.findValueProblem("\"a\\\"b\"")).isEmpty();

        assertThat(TorrcSyntax.findValueProblem("notice stdout\nControlPort 9051")).contains("contains a line break");
        assertThat(TorrcSyntax.findValueProblem("abc\0def")).contains("contains a control character");
        assertThat(TorrcSyntax.findValueProblem("abc\u001bdef")).contains("contains a control character");
        assertThat(TorrcSyntax.findValueProblem("abc#def")).contains("contains '#', which starts a comment");
        assertThat(TorrcSyntax.findValueProblem("abc \\"))
                .contains("ends with a backslash, which continues the entry on the next line");
        assertThat(TorrcSyntax.findValueProblem("\"abc\" def")).contains("is not one quoted string");
        assertThat(TorrcSyntax.findValueProblem("\"abc")).contains("is not one quoted string");
    }

    @Test
    void theQuotedStringEndsAtTheFirstQuoteWhichIsNotEscaped() {
        assertThat(TorrcSyntax.quotedStringLength("\"abc\"")).isEqualTo(5);
        assertThat(TorrcSyntax.quotedStringLength("\"a\\\"b\" # x")).isEqualTo(6);
        assertThat(TorrcSyntax.quotedStringLength("\"abc")).isEqualTo(-1);
        assertThat(TorrcSyntax.quotedStringLength("\"abc\\\"")).isEqualTo(-1);
    }

    @ParameterizedTest
    @MethodSource("quotedValues")
    void quotedValuesDecodeTorrcEscapes(String encoded, String expected) {
        assertThat(TorrcSyntax.decodeQuotedString(encoded)).isEqualTo(expected);
    }

    private static Stream<Arguments> quotedValues() {
        return Stream.of(
                Arguments.of("\"\"", ""),
                Arguments.of("\"plain # value\"", "plain # value"),
                Arguments.of("\"quote\\\"apostrophe\\'backslash\\\\\"", "quote\"apostrophe'backslash\\"),
                Arguments.of("\"a\\nb\\rc\\td\"", "a\nb\rc\td"),
                Arguments.of("\"\\1\\12\\1234\"", "\1\nS4"),
                Arguments.of("\"\\x41\\X4a\\x4F\"", "AJO"),
                // Hex and octal escapes denote bytes, not Unicode code points.
                Arguments.of("\"\u00e9\\xc3\\xbc\\303\\237\"", "\u00e9\u00fc\u00df"),
                Arguments.of("\"\ud83d\ude00\"", "\ud83d\ude00"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"plain", "\"", "\"abc", "\"abc\\\"", "\"abc\" trailing",
            "\"\\q\"", "\"\\x\"", "\"\\x1\"", "\"\\xGG\"", "\"\\400\"",
            "\"\\xc3\"", "\"\\377\"", "\"a\nb\"", "\"a\0b\""})
    void invalidQuotedValuesAreRejected(String encoded) {
        assertThatThrownBy(() -> TorrcSyntax.decodeQuotedString(encoded))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
