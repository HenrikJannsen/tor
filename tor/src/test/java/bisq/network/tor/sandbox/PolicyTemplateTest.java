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

import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyTemplateTest {
    @Test
    void replacesEveryPlaceholder() {
        String rendered = PolicyTemplate.render("a = @first@\nb = [@second@, @first@]\n",
                Map.of("first", "1", "second", "\"x\""));

        assertThat(rendered).isEqualTo("a = 1\nb = [\"x\", 1]\n");
    }

    /**
     * A placeholder without a value, or a value without a placeholder, means that the template and the code drifted
     * apart, which must stop the start rather than run with a policy that nobody wrote.
     */
    @Test
    void refusesAPlaceholderWithoutValueAndAValueWithoutPlaceholder() {
        assertThatThrownBy(() -> PolicyTemplate.render("a = @first@\nb = @second@\n", Map.of("first", "1")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("second");
        assertThatThrownBy(() -> PolicyTemplate.render("a = @first@\n", Map.of("first", "1", "other", "2")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("other");
    }

    /**
     * A value cannot end its string and add keys of its own: quotes, backslashes and control characters are escaped,
     * also the backslashes of a Windows path.
     */
    @Test
    void writesStringsThatCannotChangeThePolicy() {
        assertThat(PolicyTemplate.string("a\"b\\c\nd\te\u0001")).isEqualTo("\"a\\\"b\\\\c\\nd\\te\\u0001\"");
        assertThat(PolicyTemplate.string("C:\\Users\\x\\tor")).isEqualTo("\"C:\\\\Users\\\\x\\\\tor\"");
        assertThat(PolicyTemplate.string("\"\nread_write = [\"/\"]\n#"))
                .doesNotContain("\n")
                .startsWith("\"\\\"");
    }

    @Test
    void writesArraysAndTables() {
        assertThat(PolicyTemplate.paths(List.of())).isEqualTo("[]");
        assertThat(PolicyTemplate.paths(List.of(Paths.get("/a/./b"), Paths.get("/c"))))
                .isEqualTo("[" + PolicyTemplate.string(Paths.get("/a/b").toAbsolutePath().toString()) + ", " +
                        PolicyTemplate.string(Paths.get("/c").toAbsolutePath().toString()) + "]");
        assertThat(PolicyTemplate.table(Map.of())).isEqualTo("{}");
        assertThat(PolicyTemplate.table(Map.of("B", "2", "A", "1"))).isEqualTo("{ \"A\" = \"1\", \"B\" = \"2\" }");
    }

    @Test
    void writesOnlyBareValuesIntoTheStringsOfTheTemplate() {
        assertThat(PolicyTemplate.bare("bisq2.tor.0123abc")).isEqualTo("bisq2.tor.0123abc");
        for (String value : List.of("", "a b", "a\"b", "a\\b", "a@b")) {
            assertThatThrownBy(() -> PolicyTemplate.bare(value)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
