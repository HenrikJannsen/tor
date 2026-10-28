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

import bisq.network.tor.common.torrc.TorrcSyntax;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static bisq.network.tor.common.torrc.Torrc.Keys.CONTROL_PORT;
import static bisq.network.tor.common.torrc.Torrc.Keys.COOKIE_AUTHENTICATION;
import static bisq.network.tor.common.torrc.Torrc.Keys.COOKIE_AUTH_FILE;
import static bisq.network.tor.common.torrc.Torrc.Keys.HASHED_CONTROL_PASSWORD;
import static bisq.network.tor.common.torrc.Torrc.Keys.SOCKS_PORT;
import static bisq.network.tor.common.torrc.Torrc.Values.ExternalTor.DEFAULT_CONTROL_PORT;

/**
 * The settings for a Tor which runs outside Bisq, from the file external_tor.config. The file uses the format of a
 * torrc: one option per line, the name and the value separated by white space, and comments starting with "#", also
 * after a value. A value in double quotes can contain a "#" and C escapes. Option names are case-insensitive, as in
 * a torrc. If an option is set twice, the last value counts.
 */
@Slf4j
@Getter
@ToString
@EqualsAndHashCode
public final class ExternalTorConfig {
    static final String USE_EXTERNAL_TOR = "UseExternalTor";
    // Not an option of a torrc: the plain password for the HashedControlPassword of the external Tor
    static final String CONTROL_PASSWORD = "ControlPassword";

    // Empty if the file does not set it
    private final Optional<Boolean> useExternalTor;
    private final String controlHost;
    private final int controlPort;
    private final boolean cookieAuthentication;
    private final Optional<Path> cookieAuthFile;
    @ToString.Exclude
    private final Optional<String> controlPassword;

    private ExternalTorConfig(Optional<Boolean> useExternalTor,
                              String controlHost,
                              int controlPort,
                              boolean cookieAuthentication,
                              Optional<Path> cookieAuthFile,
                              Optional<String> controlPassword) {
        this.useExternalTor = useExternalTor;
        this.controlHost = controlHost;
        this.controlPort = controlPort;
        this.cookieAuthentication = cookieAuthentication;
        this.cookieAuthFile = cookieAuthFile;
        this.controlPassword = controlPassword;
    }

    /**
     * @throws IllegalArgumentException if a value is invalid. A setting which Bisq could misread must stop the start,
     *                                  because the user may rely on the external Tor, for example for its bridges.
     */
    public static ExternalTorConfig parse(String content) {
        Map<String, String> valueByLowerCaseKey = new LinkedHashMap<>();
        content.lines()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .forEach(line -> {
                    String[] keyAndValue = line.split("\\s+", 2);
                    String key = keyAndValue[0];
                    String value = keyAndValue.length == 2 ? parseValue(key, keyAndValue[1].trim()) : "";
                    valueByLowerCaseKey.put(key.toLowerCase(Locale.ROOT), value);
                });

        Optional<Boolean> useExternalTor = Optional.ofNullable(valueByLowerCaseKey.remove(toKey(USE_EXTERNAL_TOR)))
                .map(value -> parseBoolean(USE_EXTERNAL_TOR, value));
        String controlPortValue = Optional.ofNullable(valueByLowerCaseKey.remove(toKey(CONTROL_PORT)))
                .orElse(DEFAULT_CONTROL_PORT);
        boolean cookieAuthentication = Optional.ofNullable(valueByLowerCaseKey.remove(toKey(COOKIE_AUTHENTICATION)))
                .map(value -> parseBoolean(COOKIE_AUTHENTICATION, value))
                .orElse(false);
        Optional<Path> cookieAuthFile = Optional.ofNullable(valueByLowerCaseKey.remove(toKey(COOKIE_AUTH_FILE)))
                .map(ExternalTorConfig::parsePath);
        Optional<String> controlPassword = Optional.ofNullable(valueByLowerCaseKey.remove(toKey(CONTROL_PASSWORD)))
                .filter(password -> !password.isEmpty());
        if (cookieAuthentication && controlPassword.isPresent()) {
            throw new IllegalArgumentException("Set either " + COOKIE_AUTHENTICATION + " 1 or " + CONTROL_PASSWORD +
                    ", not both");
        }
        if (valueByLowerCaseKey.remove(toKey(HASHED_CONTROL_PASSWORD)) != null) {
            // The user copied the torrc of the external Tor. Without a cookie or a password, Bisq must not go on,
            // because the authentication would fail later with a message which does not say why.
            if (!cookieAuthentication && controlPassword.isEmpty()) {
                throw new IllegalArgumentException(HASHED_CONTROL_PASSWORD + " is the hash in the torrc of the " +
                        "external Tor. Set " + CONTROL_PASSWORD + " to the password itself, or " +
                        COOKIE_AUTHENTICATION + " 1 if the external Tor uses a cookie.");
            }
            log.warn("Bisq ignores {} of the external Tor configuration and authenticates with {}",
                    HASHED_CONTROL_PASSWORD, cookieAuthentication ? "the cookie" : CONTROL_PASSWORD);
        }
        if (valueByLowerCaseKey.remove(toKey(SOCKS_PORT)) != null) {
            // The template describes it as not required, and bisq-mobile writes it.
            log.debug("Bisq asks the external Tor for its SOCKS port and ignores {}", SOCKS_PORT);
        }
        valueByLowerCaseKey.keySet().forEach(key -> log.warn("Bisq ignores the unknown option {} of the external " +
                "Tor configuration", key));

        HostAndPort controlHostAndPort = parseHostAndPort(controlPortValue);
        return new ExternalTorConfig(useExternalTor,
                controlHostAndPort.host(),
                controlHostAndPort.port(),
                cookieAuthentication,
                cookieAuthFile,
                controlPassword);
    }

    private static String toKey(String key) {
        return key.toLowerCase(Locale.ROOT);
    }

    // As in a torrc, a "#" starts a comment, unless the value is a quoted string, in which a backslash escapes the
    // next character. The messages do not repeat the value, which can be the password.
    private static String parseValue(String key, String value) {
        if (value.startsWith("\"")) {
            int length = TorrcSyntax.quotedStringLength(value);
            if (length < 0) {
                throw new IllegalArgumentException(key + " has no closing quote");
            }
            String rest = value.substring(length).trim();
            if (!rest.isEmpty() && !rest.startsWith("#")) {
                throw new IllegalArgumentException(key + " has text after the closing quote");
            }
            try {
                return TorrcSyntax.decodeQuotedString(value.substring(0, length));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(key + " has an invalid quoted value", e);
            }
        }
        int comment = value.indexOf('#');
        return comment < 0 ? value : value.substring(0, comment).trim();
    }

    private static boolean parseBoolean(String key, String value) {
        return switch (value) {
            case "1" -> true;
            case "0" -> false;
            default -> throw new IllegalArgumentException(key + " must be 0 or 1, but is '" + value + "'");
        };
    }

    private static Path parsePath(String value) {
        try {
            return Paths.get(value);
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException(COOKIE_AUTH_FILE + " is not a valid path: '" + value + "'", e);
        }
    }

    // The forms of ControlPort which Bisq accepts: "port", "host:port" and "[IPv6 address]:port"
    private static HostAndPort parseHostAndPort(String value) {
        if (value.toLowerCase(Locale.ROOT).startsWith("unix:")) {
            throw new IllegalArgumentException("Bisq cannot connect to a Unix socket as Tor control port: " + value);
        }
        String host;
        String port;
        if (value.startsWith("[")) {
            int end = value.indexOf("]:");
            if (end < 0) {
                throw new IllegalArgumentException(CONTROL_PORT + " must be [IPv6 address]:port, but is '" + value + "'");
            }
            host = value.substring(1, end);
            port = value.substring(end + 2);
        } else if (value.contains(":")) {
            int separator = value.lastIndexOf(':');
            host = value.substring(0, separator);
            port = value.substring(separator + 1);
            if (host.contains(":")) {
                throw new IllegalArgumentException("An IPv6 address in " + CONTROL_PORT + " must be in brackets: '" +
                        value + "'");
            }
        } else {
            host = "127.0.0.1";
            port = value;
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException(CONTROL_PORT + " has no host: '" + value + "'");
        }
        return new HostAndPort(host, parsePort(value, port));
    }

    private static int parsePort(String value, String port) {
        try {
            int portNumber = Integer.parseInt(port);
            if (portNumber > 0 && portNumber <= 0xFFFF) {
                return portNumber;
            }
        } catch (NumberFormatException ignore) {
        }
        throw new IllegalArgumentException(CONTROL_PORT + " has no valid port: '" + value + "'");
    }

    private record HostAndPort(String host, int port) {
    }
}
