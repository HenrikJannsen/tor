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

import com.google.common.io.BaseEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Hashes in the output format of {@code sha256sum}: one line per file with the lowercase hex hash, two spaces (or a
 * space and {@code *}) and the file name.
 */
final class Sha256Sums {
    private static final Pattern LINE_PATTERN = Pattern.compile("^([0-9a-f]{64}) [ *](\\S+)$");

    private Sha256Sums() {
    }

    static Map<String, String> parse(String content) {
        Map<String, String> hashByFileName = new HashMap<>();
        for (String line : content.split("\n")) {
            line = line.replace("\r", "");
            if (line.isBlank()) {
                continue;
            }
            Matcher matcher = LINE_PATTERN.matcher(line);
            if (!matcher.matches()) {
                throw new IllegalArgumentException("Invalid SHA256SUMS line: " + line);
            }
            if (hashByFileName.put(matcher.group(2), matcher.group(1)) != null) {
                throw new IllegalArgumentException("Duplicate SHA256SUMS entry: " + matcher.group(2));
            }
        }
        return hashByFileName;
    }

    static String sha256Hex(InputStream inputStream) throws IOException {
        MessageDigest digest = newSha256Digest();
        byte[] buffer = new byte[64 * 1024];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        return BaseEncoding.base16().lowerCase().encode(digest.digest());
    }

    static MessageDigest newSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
