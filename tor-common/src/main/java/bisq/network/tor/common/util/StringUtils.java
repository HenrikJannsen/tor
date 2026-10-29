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

/**
 * Stripped copy of bisq.common.util.StringUtils with the methods which the Tor build uses.
 */
public class StringUtils {
    private static final String UNICODE_ELLIPSIS = "…";

    private StringUtils() {
    }

    public static String truncate(Object value, int maxLength) {
        String string = value.toString();
        int ellipsisLength = UNICODE_ELLIPSIS.length();
        if (maxLength > ellipsisLength && string.length() > maxLength) {
            int endIndex = maxLength - ellipsisLength;
            // Do not cut between the two chars of a surrogate pair (e.g. an emoji). The lone high
            // surrogate is not valid UTF-16 and gets replaced by '?' when the text is encoded as UTF-8.
            if (Character.isHighSurrogate(string.charAt(endIndex - 1))) {
                endIndex--;
            }
            return string.substring(0, endIndex) + UNICODE_ELLIPSIS;
        } else {
            return string;
        }
    }
}
