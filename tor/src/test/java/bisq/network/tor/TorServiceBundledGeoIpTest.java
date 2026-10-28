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

import bisq.network.tor.process.TorDirectories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Without GeoIPFile and GeoIPv6File, the bundled Tor reads its GeoIP files from a directory of its build below
 * /var/tmp/dist, where any local user can create files.
 */
class TorServiceBundledGeoIpTest {
    @TempDir
    Path torDir;

    @Test
    void theTorrcNamesTheGeoIpFilesOfTheBundleAlsoWhenTheyAreMissing() {
        var torDirectories = new TorDirectories(torDir);
        Map<String, String> torrc = new HashMap<>();

        TorService.putBundledGeoIpFiles(torrc, torDirectories);

        assertThat(torrc)
                .containsEntry("GeoIPFile", torDirectories.getBundledGeoIpFilePath().toAbsolutePath().toString())
                .containsEntry("GeoIPv6File", torDirectories.getBundledGeoIpv6FilePath().toAbsolutePath().toString());
    }

    @Test
    void aTorrcOverrideOfTheUserStillApplies() {
        Map<String, String> torrc = new HashMap<>(Map.of("geoipfile", "/opt/geoip"));

        TorService.putBundledGeoIpFiles(torrc, new TorDirectories(torDir));

        assertThat(torrc).containsEntry("geoipfile", "/opt/geoip").doesNotContainKey("GeoIPFile");
    }
}
