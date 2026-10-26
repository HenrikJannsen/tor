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

import bisq.network.tor.common.file.FileUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;

public class TorrcFileGenerator {
    private final Path torrcPath;
    private final Map<String, String> torrcConfigMap;
    private final List<Map.Entry<String, String>> repeatedEntries;
    private final Set<DirectoryAuthority> customDirectoryAuthorities;

    public TorrcFileGenerator(Path torrcPath,
                              Map<String, String> torrcConfigMap,
                              Set<DirectoryAuthority> customDirectoryAuthorities) {
        this(torrcPath, torrcConfigMap, List.of(), customDirectoryAuthorities);
    }

    /**
     * @param repeatedEntries entries whose key can occur more than once, for example {@code Bridge}. They follow the
     *                        entries of torrcConfigMap, in their order.
     */
    public TorrcFileGenerator(Path torrcPath,
                              Map<String, String> torrcConfigMap,
                              List<Map.Entry<String, String>> repeatedEntries,
                              Set<DirectoryAuthority> customDirectoryAuthorities) {
        this.torrcPath = torrcPath;
        this.torrcConfigMap = torrcConfigMap;
        this.repeatedEntries = List.copyOf(repeatedEntries);
        this.customDirectoryAuthorities = customDirectoryAuthorities;
    }

    /**
     * @throws IllegalArgumentException if a key or a value would not stay one entry of the torrc
     */
    public void generate() {
        StringBuilder torrcStringBuilder = new StringBuilder();
        torrcConfigMap.forEach((key, value) -> appendEntry(torrcStringBuilder, key, value));
        repeatedEntries.forEach(entry -> appendEntry(torrcStringBuilder, entry.getKey(), entry.getValue()));

        // The fields of an authority are checked by toTorrcValue, and the entry passes the value rules as well.
        customDirectoryAuthorities.forEach(dirAuthority ->
                appendEntry(torrcStringBuilder, "DirAuthority", dirAuthority.toTorrcValue()));

        try {
            FileUtils.writeToPath(torrcStringBuilder.toString(), torrcPath);
        } catch (IOException e) {
            throw new IllegalStateException("Couldn't create torrc file: " + torrcPath.toAbsolutePath());
        }
    }

    private static void appendEntry(StringBuilder torrcStringBuilder, String key, String value) {
        // A key which is not an option name would change the torrc in a way which the caller does not see: "+Key"
        // appends to a list option, "/Key" clears it, "Key#x" resets it, and "%include" reads another file. A value
        // which Tor does not read as one entry with this value would add entries, for example one which the caller
        // ignores as an override of its own keys, or drop entries, for example everything after a NUL.
        checkArgument(TorrcSyntax.isOptionName(key), "Invalid torrc key: '%s'", key);
        TorrcSyntax.findValueProblem(value).ifPresent(problem -> {
            throw new IllegalArgumentException("The value of the torrc key " + key + " " + problem);
        });
        torrcStringBuilder.append(key)
                .append(" ")
                .append(value)
                .append("\n");
    }
}
