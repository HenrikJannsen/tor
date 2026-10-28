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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SandboxedTransportsTest {
    private static final Path LYREBIRD = Paths.get("/opt/app/tor/bin/pluggable_transports/lyrebird").toAbsolutePath();

    @Test
    void withoutTransportsTorStartsNoProgram() {
        assertThat(SandboxedTransports.NONE.isEmpty()).isTrue();
        assertThat(SandboxedTransports.NONE.transportNames()).isEmpty();
        assertThat(new SandboxedTransports(Set.of("obfs4"), List.of(LYREBIRD)).isEmpty()).isFalse();
    }

    // The policy grants read and execute on the program paths, so a relative path would depend on the working directory.
    @Test
    void theProgramPathsMustBeAbsolute() {
        assertThatThrownBy(() -> new SandboxedTransports(Set.of("obfs4"),
                List.of(Paths.get("pluggable_transports/lyrebird"))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void transportsAndProgramsComeTogether() {
        assertThatThrownBy(() -> new SandboxedTransports(Set.of("obfs4"), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SandboxedTransports(Set.of(), List.of(LYREBIRD)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // The policy of a start must not change when the caller changes its collections afterwards.
    @Test
    void keepsCopiesOfItsCollections() {
        Set<String> names = new HashSet<>(Set.of("obfs4"));
        List<Path> programs = new ArrayList<>(List.of(LYREBIRD));
        var transports = new SandboxedTransports(names, programs);

        names.add("snowflake");
        programs.add(Paths.get("/usr/bin/snowflake-client"));

        assertThat(transports.transportNames()).containsExactly("obfs4");
        assertThat(transports.programPaths()).containsExactly(LYREBIRD);
    }
}
