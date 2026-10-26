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

import java.util.Optional;
import java.util.function.Function;

/**
 * Chooses the signal scope of the Tor sandbox from the exit status of {@code sandy check}: isolated signals where the
 * host can enforce them, otherwise signals to any process (Linux before 6.12, without Landlock ABI 6). Every other
 * outcome refuses the start.
 * <p>
 * Isolated signals do not break the owner check of Tor: Tor treats only {@code ESRCH} from {@code kill(pid, 0)} as
 * "owner gone", and the kernel returns {@code ESRCH} for a process that does not exist before it checks the signal
 * scope. For a live owner the scope makes the answer {@code EPERM}, which Tor reads as "alive".
 */
public final class SignalScopeSelection {
    static final int ENFORCEABLE = 0;
    static final int NOT_ENFORCEABLE = 1;

    /**
     * @param signalScope the chosen scope, or empty if Bisq must not start Tor
     * @param checkResult the check of the chosen scope, or of the isolated scope if Bisq must not start Tor
     */
    public record Selection(Optional<SandyPolicy.SignalScope> signalScope, Sandy.CheckResult checkResult) {
        public boolean isIsolationUnavailable() {
            return signalScope.equals(Optional.of(SandyPolicy.SignalScope.ANY));
        }
    }

    private SignalScopeSelection() {
    }

    /**
     * @param check runs {@code sandy check} with the policy in the given signal scope
     */
    public static Selection select(Function<SandyPolicy.SignalScope, Sandy.CheckResult> check) {
        Sandy.CheckResult isolatedCheck = check.apply(SandyPolicy.SignalScope.ISOLATED);
        if (isolatedCheck.exitCode() == ENFORCEABLE) {
            return new Selection(Optional.of(SandyPolicy.SignalScope.ISOLATED), isolatedCheck);
        }
        if (isolatedCheck.exitCode() == NOT_ENFORCEABLE) {
            Sandy.CheckResult anyCheck = check.apply(SandyPolicy.SignalScope.ANY);
            if (anyCheck.exitCode() == ENFORCEABLE) {
                return new Selection(Optional.of(SandyPolicy.SignalScope.ANY), anyCheck);
            }
        }
        return new Selection(Optional.empty(), isolatedCheck);
    }
}
