package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.TorBootstrapEvent;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class BootstrapEventParser {
    public static Optional<TorBootstrapEvent> tryParse(String[] parts) {
        // 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY="Loading relay descriptors"
        if (isBootstrapEvent(parts)) {
            TorBootstrapEvent torBootstrapEvent = parseBootstrapEvent(parts);
            return Optional.of(torBootstrapEvent);
        }

        return Optional.empty();
    }

    private static boolean isBootstrapEvent(String[] parts) {
        // 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY="Loading relay descriptors"
        return parts.length >= 7 && parts[3].equals("BOOTSTRAP");
    }


    private static TorBootstrapEvent parseBootstrapEvent(String[] parts) {
        String progress = parts[4].replace("PROGRESS=", "");
        String tag = parts[5].replace("TAG=", "");
        String summary = parseBootstrapSummary(parts);

        int progressInt = Integer.parseInt(progress);
        return new TorBootstrapEvent(progressInt, tag, summary);
    }

    private static String parseBootstrapSummary(String[] parts) {
        // SUMMARY="Loading relay descriptors" has whitespaces in string. A warning adds WARNING and REASON, which the
        // summary keeps, and HOSTID and HOSTADDR, the relay or bridge to which Tor failed to connect. These must not
        // end up in the log of the application, where they would make known a bridge that the user obtained privately.
        Map<String, String> arguments = parseArguments(String.join(" ", Arrays.copyOfRange(parts, 6, parts.length)));
        String summary = arguments.getOrDefault("SUMMARY", "");
        if (summary.isEmpty() || !arguments.containsKey("WARNING")) {
            return summary;
        }
        String reason = arguments.containsKey("REASON") ? ", " + arguments.get("REASON") : "";
        return summary + " (" + arguments.get("WARNING") + reason + ")";
    }

    // KEY=value or KEY="quoted value", separated by a space. A quoted value can hold an escaped quote. A quoted value
    // without its closing quote ends the arguments, so that it cannot take the arguments after it.
    private static Map<String, String> parseArguments(String arguments) {
        Map<String, String> parsedArguments = new HashMap<>();
        int keyStart = 0;
        while (keyStart < arguments.length()) {
            int equals = arguments.indexOf('=', keyStart);
            if (equals < 0) {
                break;
            }
            String key = arguments.substring(keyStart, equals).trim();
            int valueStart = equals + 1;
            int valueEnd;
            String value;
            if (valueStart < arguments.length() && arguments.charAt(valueStart) == '"') {
                int quoteEnd = valueStart + 1;
                while (quoteEnd < arguments.length() && arguments.charAt(quoteEnd) != '"') {
                    quoteEnd += arguments.charAt(quoteEnd) == '\\' ? 2 : 1;
                }
                if (quoteEnd >= arguments.length()) {
                    break;
                }
                value = arguments.substring(valueStart + 1, quoteEnd);
                valueEnd = quoteEnd + 1;
            } else {
                int space = arguments.indexOf(' ', valueStart);
                valueEnd = space < 0 ? arguments.length() : space;
                value = arguments.substring(valueStart, valueEnd);
            }
            parsedArguments.putIfAbsent(key, value);
            keyStart = valueEnd + 1;
        }
        return parsedArguments;
    }
}
