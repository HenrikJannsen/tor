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

package bisq.network.tor.local_network;

import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.common.torrc.TorrcConfigGenerator;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.local_network.torrc.TestNetworkTorrcGeneratorFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class RelayTorrcGeneratorTests {
    @Test
    void basicTest(@TempDir Path tempDirPath) throws IOException {
        Path relayAPath = tempDirPath.resolve("RELAY_A");
        FileUtils.createDirectory(relayAPath);

        TorNode firstRelay = spy(
                TorNode.builder()
                        .type(TorNode.Type.RELAY)
                        .nickname("A")
                        .dataDirPath(relayAPath)

                        .orPort(2)
                        .dirPort(3)

                        .build()
        );

        doReturn(Optional.of("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                .when(firstRelay)
                .getAuthorityIdentityKeyFingerprint();

        doReturn(Optional.of("1111111111111111111111111111111111111111"))
                .when(firstRelay)
                .getRelayKeyFingerprint();

        TorNode secondRelay = spy(
                TorNode.builder()
                        .type(TorNode.Type.RELAY)
                        .nickname("B")
                        .dataDirPath(tempDirPath.resolve("DA_B"))

                        .orPort(2)
                        .dirPort(3)

                        .build()
        );

        doReturn(Optional.of("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
                .when(secondRelay)
                .getAuthorityIdentityKeyFingerprint();

        doReturn(Optional.of("2222222222222222222222222222222222222222"))
                .when(secondRelay)
                .getRelayKeyFingerprint();

        TorrcConfigGenerator relayTorrcGenerator = TestNetworkTorrcGeneratorFactory.relayTorrcGenerator(firstRelay);
        Map<String, String> torrcConfigs = relayTorrcGenerator.generate();

        TorNode dirAuth = spy(
                TorNode.builder()
                        .type(TorNode.Type.DIRECTORY_AUTHORITY)
                        .nickname("A")
                        .dataDirPath(tempDirPath.resolve("dir_auth"))

                        .orPort(2)
                        .dirPort(3)

                        .build()
        );

        doReturn(Optional.of("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                .when(dirAuth)
                .getAuthorityIdentityKeyFingerprint();

        doReturn(Optional.of("1111111111111111111111111111111111111111"))
                .when(dirAuth)
                .getRelayKeyFingerprint();

        Path torrcPath = firstRelay.getTorrcPath();
        Set<DirectoryAuthority> allDAs = Set.of(dirAuth.toDirectoryAuthority());
        var torrcFileGenerator = new TorrcFileGenerator(torrcPath, torrcConfigs, allDAs);
        torrcFileGenerator.generate();

        assertThat(firstRelay.getTorrcPath())
                .isNotEmptyFile();
    }
}
