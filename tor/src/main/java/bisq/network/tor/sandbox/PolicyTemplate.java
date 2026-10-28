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

package bisq.network.tor.sandbox;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Fills in a sandy policy template. A placeholder {@code @name@} stands for a value of the start. Each value is
 * written as valid TOML where it stands, so no path, variable or port can change the structure of the policy: the
 * helpers of this class write strings, arrays and tables, and a placeholder inside a TOML string of the template takes
 * a name that is checked to need no escaping. Every placeholder must get a value and every value a placeholder, so a
 * template and the code cannot drift apart unnoticed.
 */
final class PolicyTemplate {
    private static final Pattern PLACEHOLDER = Pattern.compile("@([a-z_]+)@");

    private PolicyTemplate() {
    }

    static String render(String template, Map<String, String> values) {
        Matcher matcher = PLACEHOLDER.matcher(template);
        StringBuilder rendered = new StringBuilder();
        Set<String> used = new HashSet<>();
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = values.get(name);
            checkArgument(value != null, "The sandy policy template has a placeholder without a value: %s", name);
            used.add(name);
            matcher.appendReplacement(rendered, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(rendered);
        List<String> unused = values.keySet().stream().filter(name -> !used.contains(name)).sorted().toList();
        checkArgument(unused.isEmpty(), "The sandy policy template has no placeholder for: %s", unused);
        return rendered.toString();
    }

    static String string(String value) {
        StringBuilder quoted = new StringBuilder("\"");
        value.codePoints().forEach(codePoint -> {
            switch (codePoint) {
                case '"' -> quoted.append("\\\"");
                case '\\' -> quoted.append("\\\\");
                case '\n' -> quoted.append("\\n");
                case '\r' -> quoted.append("\\r");
                case '\t' -> quoted.append("\\t");
                default -> {
                    if (codePoint < 0x20 || codePoint == 0x7f) {
                        quoted.append(String.format("\\u%04X", codePoint));
                    } else {
                        quoted.appendCodePoint(codePoint);
                    }
                }
            }
        });
        return quoted.append('"').toString();
    }

    static String path(Path path) {
        return string(path.toAbsolutePath().normalize().toString());
    }

    static String paths(List<Path> paths) {
        return "[" + paths.stream().map(PolicyTemplate::path).collect(Collectors.joining(", ")) + "]";
    }

    static String table(Map<String, String> entries) {
        if (entries.isEmpty()) {
            return "{}";
        }
        return "{ " + entries.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> string(entry.getKey()) + " = " + string(entry.getValue()))
                .collect(Collectors.joining(", ")) + " }";
    }

    /**
     * A value that the template writes inside a TOML string, such as an AppContainer name with a suffix of the
     * template. Only characters that need no escaping are allowed.
     */
    static String bare(String value) {
        checkArgument(value.matches("[A-Za-z0-9._-]+"), "Not a bare value: %s", value);
        return value;
    }
}
