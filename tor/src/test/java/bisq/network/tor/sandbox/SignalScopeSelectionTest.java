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

import bisq.network.tor.sandbox.SandyPolicy.SignalScope;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SignalScopeSelectionTest {
    private final List<SignalScope> checkedScopes = new ArrayList<>();

    @Test
    void choosesIsolatedSignalsWhenTheHostCanEnforceThem() {
        SignalScopeSelection.Selection selection = select(Map.of(SignalScope.ISOLATED, 0, SignalScope.ANY, 0));

        assertThat(selection.signalScope()).contains(SignalScope.ISOLATED);
        assertThat(selection.isIsolationUnavailable()).isFalse();
        assertThat(selection.checkResult().output()).isEqualTo("isolated");
        assertThat(checkedScopes).containsExactly(SignalScope.ISOLATED);
    }

    @Test
    void fallsBackToAnySignalsWhenOnlyIsolationIsNotEnforceable() {
        SignalScopeSelection.Selection selection = select(Map.of(SignalScope.ISOLATED, 1, SignalScope.ANY, 0));

        assertThat(selection.signalScope()).contains(SignalScope.ANY);
        assertThat(selection.isIsolationUnavailable()).isTrue();
        assertThat(selection.checkResult().output()).isEqualTo("any");
        assertThat(checkedScopes).containsExactly(SignalScope.ISOLATED, SignalScope.ANY);
    }

    @Test
    void refusesWhenNoScopeIsEnforceable() {
        SignalScopeSelection.Selection selection = select(Map.of(SignalScope.ISOLATED, 1, SignalScope.ANY, 1));

        assertThat(selection.signalScope()).isEmpty();
        // The refusal reports the check of the requested, isolated policy.
        assertThat(selection.checkResult().output()).isEqualTo("isolated");
    }

    @Test
    void refusesWhenTheCheckFails() {
        // 125: sandy failed or refused the policy; -1: the check did not finish.
        for (int exitCode : new int[]{125, -1}) {
            checkedScopes.clear();

            SignalScopeSelection.Selection selection = select(Map.of(SignalScope.ISOLATED, exitCode, SignalScope.ANY, 0));

            assertThat(selection.signalScope()).isEqualTo(Optional.empty());
            assertThat(selection.checkResult().exitCode()).isEqualTo(exitCode);
            assertThat(checkedScopes).containsExactly(SignalScope.ISOLATED);
        }
    }

    private SignalScopeSelection.Selection select(Map<SignalScope, Integer> exitCodeByScope) {
        return SignalScopeSelection.select(scope -> {
            checkedScopes.add(scope);
            return new Sandy.CheckResult(exitCodeByScope.get(scope), scope.getOptionValue());
        });
    }
}
