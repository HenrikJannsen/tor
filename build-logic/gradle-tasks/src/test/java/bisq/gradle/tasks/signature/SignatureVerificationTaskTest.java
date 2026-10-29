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

package bisq.gradle.tasks.signature;

import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Hex;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Date;
import java.util.Map;

import static bisq.gradle.tasks.signature.KeyFixture.CREATED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureVerificationTaskTest {
    private static final byte[] BUNDLE = "the bytes of a bundle".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path directory;

    @Test
    void verifiesTheFileWithThePinnedHashAndAValidSignature() throws Exception {
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        SignatureVerificationTask task = task(fixture, BUNDLE, sha256(BUNDLE));

        task.verify();

        assertEquals("true", Files.readString(task.getResultFile().get().getAsFile().toPath()));
    }

    @Test
    void refusesAValidlySignedFileWithAnotherHashBeforeItsSignature() throws Exception {
        // As an older release of the same signer would be
        KeyFixture fixture = KeyFixture.create(0, true, KeyFlags.SIGN_DATA);
        SignatureVerificationTask task = task(fixture, BUNDLE, sha256("the pinned bundle".getBytes(StandardCharsets.US_ASCII)));
        Files.writeString(task.getDetachedSignatureFile().get().getAsFile().toPath(), "not a signature\n");

        GradleException exception = assertThrows(GradleException.class, task::verify);
        assertTrue(exception.getMessage().contains("the pinned SHA-256 is"), exception.getMessage());
        assertEquals("false", Files.readString(task.getResultFile().get().getAsFile().toPath()));
    }

    private SignatureVerificationTask task(KeyFixture fixture, byte[] bundle, String expectedSha256) throws Exception {
        Path bundlePath = directory.resolve("bundle.tar.gz");
        Files.write(bundlePath, bundle);
        Path signaturePath = directory.resolve("bundle.tar.gz.asc");
        Files.write(signaturePath, KeyFixture.armoredSignature(fixture.subkey(), PGPSignature.BINARY_DOCUMENT,
                new Date(CREATED.getTime() + 30_000), bundle));
        Path keyPath = directory.resolve("key.pgp");
        Files.write(keyPath, fixture.ring().getEncoded());
        String fingerprint = Hex.toHexString(fixture.ring().getPublicKey().getFingerprint());

        Project project = ProjectBuilder.builder().withProjectDir(directory.resolve("project").toFile()).build();
        SignatureVerificationTask task = project.getTasks().register("verifyBinary", SignatureVerificationTask.class).get();
        task.getFileToVerify().set(bundlePath.toFile());
        task.getExpectedSha256().set(expectedSha256);
        task.getDetachedSignatureFile().set(signaturePath.toFile());
        task.getPgpFingerprintToKeyUrl().set(Map.of(fingerprint, keyPath.toUri().toString()));
        task.getPgpFingerprintToKeySha256().set(Map.of(fingerprint, sha256(fixture.ring().getEncoded())));
        task.getResultFile().set(directory.resolve("sha256.result").toFile());
        return task;
    }

    private static String sha256(byte[] bytes) throws Exception {
        return Hex.toHexString(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
