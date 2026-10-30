package bisq.gradle.tor_binary;

import bisq.gradle.common.Platform;
import bisq.gradle.tasks.signature.SignatureVerifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Ensures the signed release resource contains a bundle for every supported platform. */
class TorSignedChecksumsTest {
    private static final Path GRADLE_PROPERTIES = Path.of("../../gradle.properties");
    private static final String PRIMARY_KEY_FINGERPRINT = "ef6e286dda85ea2a4ba7de684e2c6e8793298290";

    @Test
    void theReleaseHasSignedChecksumsForEverySupportedPlatform() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(GRADLE_PROPERTIES)) {
            properties.load(input);
        }
        String version = properties.getProperty("tor.version");
        byte[] checksums = resource("torbrowser-" + version + "/sha256sums-signed-build.txt");
        byte[] signature = resource("torbrowser-" + version + "/sha256sums-signed-build.txt.asc");
        String keyUrl = BisqTorBinaryPlugin.class.getResource("/Tor_Browser_Developers_(signing_key).asc").toString();
        assertTrue(new SignatureVerifier(Map.of(PRIMARY_KEY_FINGERPRINT, keyUrl))
                .verifySignature(checksums, signature), "The release checksum signature does not verify");

        String signedEntries = new String(checksums, java.nio.charset.StandardCharsets.UTF_8);
        for (Platform platform : Platform.values()) {
            String url = new TorBinaryUrlProvider(version).urlFor(platform);
            if (url == null) {
                continue;
            }
            String fileName = url.substring(url.lastIndexOf('/') + 1);
            long count = signedEntries.lines().filter(line -> line.endsWith("  " + fileName)).count();
            assertEquals(1, count, "Expected one signed checksum for " + fileName);
        }
    }

    private static byte[] resource(String path) throws IOException {
        InputStream stream = TorSignedChecksumsTest.class.getResourceAsStream("/" + path);
        assertNotNull(stream, "Missing signed release resource: " + path);
        try (stream) {
            return stream.readAllBytes();
        }
    }
}
