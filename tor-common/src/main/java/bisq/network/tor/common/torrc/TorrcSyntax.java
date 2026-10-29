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

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The rules by which Tor reads an entry of a torrc. Tor splits a line at white space into the option name and the
 * value. The name ends at a "#" as well; a name with the prefix "+" appends to a list option, a name with the prefix
 * "/" clears it, and "%include" reads another file. The value runs to the end of the line or to a "#", which starts a
 * comment, unless it is a quoted string with C escapes. A backslash at the end of a line continues the entry on the
 * next line, and Tor reads the file as a C string, so a NUL ends it.
 */
public final class TorrcSyntax {
    // The name of a Tor option: letters and digits, after "__" for a hidden option
    private static final Pattern OPTION_NAME = Pattern.compile("_{0,2}[A-Za-z][A-Za-z0-9]*");

    private TorrcSyntax() {
    }

    public static boolean isOptionName(String key) {
        return OPTION_NAME.matcher(key).matches();
    }

    /**
     * @return the value as Tor reads it whole: unchanged where Tor reads it so, otherwise a quoted string with C
     * escapes, for example for a path with "#", which would start a comment. Control characters stay as they are, so
     * that {@link #findValueProblem} still refuses them.
     */
    public static String toValue(String value) {
        boolean isReadWhole = value.indexOf('#') < 0 && !value.startsWith("\"") && !value.endsWith("\\") &&
                value.equals(value.strip());
        if (isReadWhole) {
            return value;
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * @return why Tor would not read the value as one entry with this value, or empty if it would
     */
    public static Optional<String> findValueProblem(String value) {
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return Optional.of("contains a line break");
        }
        if (value.chars().anyMatch(TorrcSyntax::isControlCharacter)) {
            return Optional.of("contains a control character");
        }
        if (value.startsWith("\"")) {
            return quotedStringLength(value) == value.length() ? Optional.empty() : Optional.of("is not one quoted string");
        }
        if (value.indexOf('#') >= 0) {
            return Optional.of("contains '#', which starts a comment");
        }
        if (value.endsWith("\\")) {
            return Optional.of("ends with a backslash, which continues the entry on the next line");
        }
        return Optional.empty();
    }

    /**
     * @param value a value which starts with a quote
     * @return the length of the quoted string at the start of the value, with both quotes, or -1 if the closing quote
     *         is missing. A backslash escapes the next character.
     */
    public static int quotedStringLength(String value) {
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '"') {
                return i + 1;
            }
        }
        return -1;
    }

    /**
     * Decodes one quoted torrc value. Tor's numeric C escapes represent bytes, so escaped UTF-8 bytes and literal
     * UTF-8 characters must be decoded together.
     *
     * @throws IllegalArgumentException if the syntax or decoded UTF-8 is invalid. The message omits the value,
     *                                  which may be a password.
     */
    public static String decodeQuotedString(String value) {
        if (!value.startsWith("\"") || quotedStringLength(value) != value.length()) {
            throw new IllegalArgumentException("Value is not one quoted torrc string");
        }
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        byte[] decoded = new byte[encoded.length - 2];
        int length = 0;
        int end = encoded.length - 1;
        for (int i = 1; i < end; i++) {
            int character = encoded[i];
            if (character == 0 || character == '\n') {
                throw new IllegalArgumentException("Quoted torrc value contains a NUL or line break");
            }
            if (character == '\\') {
                switch (encoded[++i]) {
                    case 'n' -> character = '\n';
                    case 'r' -> character = '\r';
                    case 't' -> character = '\t';
                    case '\'', '"', '\\' -> character = encoded[i];
                    case 'x', 'X' -> {
                        if (i + 2 >= end) {
                            throw new IllegalArgumentException("Incomplete hex escape in quoted torrc value");
                        }
                        int high = Character.digit((char) encoded[++i], 16);
                        int low = Character.digit((char) encoded[++i], 16);
                        if (high < 0 || low < 0) {
                            throw new IllegalArgumentException("Invalid hex escape in quoted torrc value");
                        }
                        character = high * 16 + low;
                    }
                    default -> {
                        if (encoded[i] < '0' || encoded[i] > '7') {
                            throw new IllegalArgumentException("Invalid escape in quoted torrc value");
                        }
                        character = encoded[i] - '0';
                        for (int digits = 1; digits < 3 && i + 1 < end &&
                                encoded[i + 1] >= '0' && encoded[i + 1] <= '7'; digits++) {
                            character = character * 8 + encoded[++i] - '0';
                        }
                        if (character > 255) {
                            throw new IllegalArgumentException("Octal escape exceeds one byte in quoted torrc value");
                        }
                    }
                }
            }
            decoded[length++] = (byte) character;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(decoded, 0, length)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Quoted torrc value is not valid UTF-8", e);
        }
    }

    // Tab is white space in a value; the other control characters have no use in an option value.
    private static boolean isControlCharacter(int c) {
        return (c < 0x20 && c != '\t') || c == 0x7f;
    }
}
