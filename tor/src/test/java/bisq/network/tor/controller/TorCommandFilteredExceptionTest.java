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

package bisq.network.tor.controller;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TorCommandFilteredExceptionTest {
    @Test
    void onWhonixTheMessageNamesTheProfileOfBisq() {
        assertThat(TorCommandFilteredException.createMessage("ADD_ONION", true))
                .contains("ADD_ONION", "sudo onion-grater-add 40_bisq");
        assertThat(TorCommandFilteredException.createMessage("ADD_ONION", false))
                .contains("ADD_ONION")
                .doesNotContain("onion-grater");
    }
}
