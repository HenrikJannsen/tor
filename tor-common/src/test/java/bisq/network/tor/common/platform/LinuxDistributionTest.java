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

package bisq.network.tor.common.platform;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

// The markers of the packages whonix-base-files, anon-ws-base-files and anon-gw-base-files of Whonix
class LinuxDistributionTest {
    @TempDir
    Path fileSystemRoot;

    @Test
    void aWorkstationIsWhonixButNoGateway() throws IOException {
        createWhonixMarkers();
        createFile("usr/share/anon-ws-base-files/workstation");

        assertThat(LinuxDistribution.isWhonix(fileSystemRoot)).isTrue();
        assertThat(LinuxDistribution.isWhonixGateway(fileSystemRoot)).isFalse();
    }

    @Test
    void aGatewayIsWhonixAndAGateway() throws IOException {
        createWhonixMarkers();
        createFile("usr/share/anon-gw-base-files/gateway");

        assertThat(LinuxDistribution.isWhonix(fileSystemRoot)).isTrue();
        assertThat(LinuxDistribution.isWhonixGateway(fileSystemRoot)).isTrue();
    }

    @Test
    void theMarkerOfTheGatewayAloneIsNoWhonix() throws IOException {
        createFile("usr/share/anon-gw-base-files/gateway");
        assertThat(LinuxDistribution.isWhonixGateway(fileSystemRoot)).isFalse();

        createFile("usr/share/whonix/marker");
        assertThat(LinuxDistribution.isWhonix(fileSystemRoot)).isFalse();
        assertThat(LinuxDistribution.isWhonixGateway(fileSystemRoot)).isFalse();
    }

    @Test
    void aDirectoryIsNoMarker() throws IOException {
        createFile("usr/share/whonix/marker");
        Files.createDirectories(fileSystemRoot.resolve("usr/share/anon-dist/marker"));

        assertThat(LinuxDistribution.isWhonix(fileSystemRoot)).isFalse();
    }

    private void createWhonixMarkers() throws IOException {
        createFile("usr/share/whonix/marker");
        createFile("usr/share/anon-dist/marker");
    }

    private void createFile(String path) throws IOException {
        Path file = fileSystemRoot.resolve(path);
        Files.createDirectories(file.getParent());
        Files.createFile(file);
    }
}
