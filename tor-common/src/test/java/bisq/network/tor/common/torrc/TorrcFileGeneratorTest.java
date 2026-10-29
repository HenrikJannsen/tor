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
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TorrcFileGeneratorTest {
    @TempDir
    Path tempDir;

    @Test
    void writesOneLinePerEntry() throws IOException {
        Map<String, String> torrc = new LinkedHashMap<>();
        torrc.put("DataDirectory", "/home/user/tor");
        torrc.put("Log", "notice file /home/user/tor/debug.log");
        Path torrcPath = tempDir.resolve("torrc");

        new TorrcFileGenerator(torrcPath, torrc, Set.of()).generate();

        assertThat(Files.readString(torrcPath))
                .isEqualTo("DataDirectory /home/user/tor\nLog notice file /home/user/tor/debug.log\n");
    }

    @Test
    void aLineBreakInAValueCannotAddAnEntry() {
        // For example a torrc override of the user, which would otherwise set a key that the caller ignores
        Map<String, String> torrc = Map.of("Log", "notice stdout\nControlPort 9051");
        Path torrcPath = tempDir.resolve("torrc");

        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, torrc, Set.of()).generate())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("line break");
        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, Map.of("Log", "notice stdout\rx"), Set.of()).generate())
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(torrcPath).doesNotExist();
    }

    @Test
    void aValueWhichTorWouldNotReadAsOneEntryIsRefused() {
        // Tor reads the torrc as a C string, so a NUL ends it; a "#" starts a comment, and a backslash at the end of
        // the line continues the entry on the next line (checked with tor 0.4.9.14).
        Path torrcPath = tempDir.resolve("torrc");
        Map<String, String> problemByValue = new LinkedHashMap<>();
        problemByValue.put("notice stdout\0ControlPort 9051", "control character");
        problemByValue.put("notice stdout # ControlPort 9051", "comment");
        problemByValue.put("notice stdout \\", "backslash");
        problemByValue.put("\"notice stdout\" x", "quoted string");

        problemByValue.forEach((value, problem) -> {
            assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, Map.of("Log", value), Set.of()).generate())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Log")
                    .hasMessageContaining(problem);
        });
        assertThat(torrcPath).doesNotExist();
    }

    @Test
    void everyGeneratorOfTheModuleWritesATorrc() throws IOException {
        // The generators and the value rules of the file generator must agree: a constant value which the rules
        // refuse would otherwise fail every start of that node type.
        TorrcConfigGenerator baseGenerator = BaseTorrcGenerator.builder()
                .dataDirPath(tempDir.resolve("data"))
                .hashedControlPassword("16:00")
                .build();
        TorrcConfigGenerator testNetworkGenerator = TestNetworkTorrcGenerator.builder()
                .baseTorrcConfigGenerator(baseGenerator)
                .nickname(Optional.of("da0"))
                .orPort(Optional.of(5000))
                .dirPort(Optional.of(5001))
                .build();
        Map<String, TorrcConfigGenerator> generatorByNodeType = new LinkedHashMap<>();
        generatorByNodeType.put("directory-authority", new DirectoryAuthorityTorrcGenerator(testNetworkGenerator, "da0"));
        generatorByNodeType.put("relay", new RelayTorrcGenerator(testNetworkGenerator));
        generatorByNodeType.put("client", ClientTorrcGenerator.builder().baseTorrcConfigGenerator(testNetworkGenerator).build());
        DirectoryAuthority authority = DirectoryAuthority.builder()
                .nickname("da0")
                .orPort(5000)
                .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                .dirPort(5001)
                .relayFingerprint("89ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .build();

        generatorByNodeType.forEach((nodeType, generator) -> {
            Path torrcPath = tempDir.resolve(nodeType + ".torrc");
            new TorrcFileGenerator(torrcPath, generator.generate(), Set.of(authority)).generate();
            assertThat(torrcPath).isNotEmptyFile();
        });
        assertThat(Files.readString(tempDir.resolve("directory-authority.torrc")))
                .contains("ContactInfo auth-da0@test.test\n")
                .contains("DirAuthority da0 orport=5000 v3ident=0123456789ABCDEF0123456789ABCDEF01234567 " +
                        "127.0.0.1:5001 89ABCDEF0123456789ABCDEF0123456789ABCDEF\n");
    }

    @Test
    void aDirectoryAuthorityIsWrittenAsOneEntry() throws IOException {
        Path torrcPath = tempDir.resolve("torrc");
        DirectoryAuthority authority = directoryAuthority("89ABCDEF0123456789ABCDEF0123456789ABCDEF");

        new TorrcFileGenerator(torrcPath, Map.of(), Set.of(authority)).generate();

        assertThat(Files.readString(torrcPath)).isEqualTo("DirAuthority da0 orport=5000 " +
                "v3ident=0123456789ABCDEF0123456789ABCDEF01234567 127.0.0.1:5001 " +
                "89ABCDEF0123456789ABCDEF0123456789ABCDEF\n");
    }

    @Test
    void aDirectoryAuthorityFieldWhichTorWouldNotReadAsOneEntryIsRefused() {
        // The fields come from the configuration. A line break in one of them would add an entry after the
        // generated settings, here a second DisableNetwork.
        Path torrcPath = tempDir.resolve("torrc");
        Map<String, String> torrc = Map.of("DisableNetwork", "1");

        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, torrc,
                Set.of(directoryAuthority("B".repeat(40) + "\nDisableNetwork 0"))).generate())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fingerprint");
        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, torrc,
                Set.of(directoryAuthority("B".repeat(40) + " #"))).generate())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, torrc,
                Set.of(DirectoryAuthority.builder().nickname("da 0").orPort(5000).dirPort(5001)
                        .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                        .relayFingerprint("89ABCDEF0123456789ABCDEF0123456789ABCDEF").build())).generate())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nickname");
        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, torrc,
                Set.of(DirectoryAuthority.builder().nickname("da0").orPort(0).dirPort(5001)
                        .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                        .relayFingerprint("89ABCDEF0123456789ABCDEF0123456789ABCDEF").build())).generate())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("orport");
        assertThat(torrcPath).doesNotExist();
    }

    private static DirectoryAuthority directoryAuthority(String relayFingerprint) {
        return DirectoryAuthority.builder()
                .nickname("da0")
                .orPort(5000)
                .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                .dirPort(5001)
                .relayFingerprint(relayFingerprint)
                .build();
    }

    @Test
    void aQuotedValueCanContainAComment() throws IOException {
        Path torrcPath = tempDir.resolve("torrc");

        new TorrcFileGenerator(torrcPath, Map.of("ContactInfo", "\"abc#def\""), Set.of()).generate();

        assertThat(Files.readString(torrcPath)).isEqualTo("ContactInfo \"abc#def\"\n");
    }

    @Test
    void aKeyWhichIsNotAnOptionNameIsRefused() {
        // Tor reads these forms as a change of the option ControlPort, which a rule about the key ControlPort would
        // not see, and %include reads another file.
        Path torrcPath = tempDir.resolve("torrc");

        for (String key : List.of("+ControlPort", "/ControlPort", "ControlPort#x", "%include")) {
            assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, Map.of(key, "127.0.0.1:19051"), Set.of()).generate())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(key);
        }
        assertThat(torrcPath).doesNotExist();
    }

    @Test
    void aHiddenOptionIsAKey() throws IOException {
        Path torrcPath = tempDir.resolve("torrc");

        new TorrcFileGenerator(torrcPath, Map.of("__OwningControllerProcess", "4711"), Set.of()).generate();

        assertThat(Files.readString(torrcPath)).isEqualTo("__OwningControllerProcess 4711\n");
    }

    @Test
    void aKeyWithWhiteSpaceIsRefused() {
        Path torrcPath = tempDir.resolve("torrc");

        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, Map.of("Log notice", "stdout"), Set.of()).generate())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TorrcFileGenerator(torrcPath, Map.of("", "stdout"), Set.of()).generate())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
