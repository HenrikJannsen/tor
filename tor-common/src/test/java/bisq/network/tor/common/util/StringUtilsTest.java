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
package bisq.network.tor.common.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class StringUtilsTest {
    @Test
    void truncateKeepsShortValues() {
        assertThat(StringUtils.truncate("abc", 3)).isEqualTo("abc");
        assertThat(StringUtils.truncate("abc", 1)).isEqualTo("abc");
    }

    @Test
    void truncateReplacesTheEndWithAnEllipsis() {
        assertThat(StringUtils.truncate("abcdef", 4)).isEqualTo("abc…");
        assertThat(StringUtils.truncate(123456, 4)).isEqualTo("123…");
    }

    @Test
    void truncateDoesNotSplitASurrogatePair() {
        // One code point stored as two chars, a high and a low surrogate
        String emoji = "😀";

        // The cut falls between the two chars of the emoji, so the emoji is dropped as a whole
        assertThat(StringUtils.truncate("1" + emoji + "45", 3)).isEqualTo("1…");
        assertThat(StringUtils.truncate(emoji + emoji + "5", 4)).isEqualTo(emoji + "…");
        assertThat(StringUtils.truncate(emoji + "345", 2)).isEqualTo("…");

        // The cut falls right after the emoji, so the emoji is kept
        assertThat(StringUtils.truncate("1" + emoji + "456", 4)).isEqualTo("1" + emoji + "…");
        assertThat(StringUtils.truncate(emoji + "345", 3)).isEqualTo(emoji + "…");
    }

    @Test
    void truncateNeverOutputsAnUnpairedSurrogate() {
        String text = "a😀bc😀😀d🇩🇪";
        for (int maxLength = 2; maxLength <= text.length() + 1; maxLength++) {
            String truncated = StringUtils.truncate(text, maxLength);

            assertThat(truncated.length()).as("maxLength=" + maxLength).isLessThanOrEqualTo(maxLength);
            // An unpaired surrogate does not survive encoding, it comes back as '?'
            String decoded = new String(truncated.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
            assertThat(decoded).as("maxLength=" + maxLength).isEqualTo(truncated);
        }
    }
}
