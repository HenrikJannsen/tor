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

package bisq.gradle.tor_binary;

import bisq.gradle.common.Platform;
import bisq.gradle.tasks.signature.SignatureVerifier;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The SHA-256 pins of the expert bundles in gradle.properties are copies of sha256sums-signed-build.txt of the release
 * tor.version, which the Tor Browser developers sign. The test resources keep that file of the release with its
 * signature, so the pins are checked against their signed source.
 */
class TorBundlePinsTest {
    // The test runs in the directory of this project, build-logic/tor-binary
    private static final Path GRADLE_PROPERTIES = Path.of("../../gradle.properties");
    private static final String PRIMARY_KEY_FINGERPRINT = "ef6e286dda85ea2a4ba7de684e2c6e8793298290";

    @Test
    void thePinsAreTheSignedHashesOfTheBundlesOfTheRelease() throws IOException, URISyntaxException {
        Properties gradleProperties = new Properties();
        try (InputStream inputStream = Files.newInputStream(GRADLE_PROPERTIES)) {
            gradleProperties.load(inputStream);
        }
        String torVersion = gradleProperties.getProperty("tor.version");
        File sums = resource("torbrowser-" + torVersion + "/sha256sums-signed-build.txt");
        File signature = resource("torbrowser-" + torVersion + "/sha256sums-signed-build.txt.asc");
        String keyUrl = BisqTorBinaryPlugin.class.getResource("/Tor_Browser_Developers_(signing_key).asc").toString();
        assertTrue(new SignatureVerifier(Map.of(PRIMARY_KEY_FINGERPRINT, keyUrl)).verifySignature(sums, signature),
                "The signature of " + sums + " does not verify");
        Map<String, String> signedSha256ByFileName = new HashMap<>();
        for (String line : Files.readAllLines(sums.toPath())) {
            String[] hashAndFileName = line.split(" +");
            signedSha256ByFileName.put(hashAndFileName[1], hashAndFileName[0]);
        }

        for (Platform platform : Platform.values()) {
            String url = new TorBinaryUrlProvider(torVersion).urlFor(platform);
            if (url == null) {
                continue;
            }
            String fileName = url.substring(url.lastIndexOf('/') + 1);
            String pinnedSha256 = gradleProperties.getProperty("tor.bundleSha256." + platform.getPlatformName());
            assertNotNull(pinnedSha256, "No pin for " + platform.getPlatformName());
            assertEquals(signedSha256ByFileName.get(fileName), pinnedSha256, fileName);
        }
    }

    private static File resource(String name) throws URISyntaxException {
        URL url = TorBundlePinsTest.class.getResource("/" + name);
        assertNotNull(url, name + " is missing: add the signed checksums of the release to the test resources");
        return new File(url.toURI());
    }
}
