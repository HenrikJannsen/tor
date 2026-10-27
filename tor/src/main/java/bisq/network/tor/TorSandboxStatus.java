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

package bisq.network.tor;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * Whether the Tor of the current start runs in the sandbox, and if not, why. TorService sets it during the start, so
 * that the application can tell the user. It reports {@link State#SANDBOXED} only once the Tor of the start answers on
 * its control port, with the level in which sandy started it; a start which fails before keeps
 * {@link State#NOT_STARTED}.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class TorSandboxStatus {
    public enum State {
        // Tor was not started yet.
        NOT_STARTED,
        // Tor runs in the sandbox.
        SANDBOXED,
        // Bisq uses a Tor which it did not start, so it cannot put that Tor into its sandbox.
        EXTERNAL_TOR,
        // The configuration turns the sandbox off.
        DISABLED
    }

    public static final TorSandboxStatus NOT_STARTED = new TorSandboxStatus(State.NOT_STARTED, "", false, false);
    public static final TorSandboxStatus EXTERNAL_TOR = new TorSandboxStatus(State.EXTERNAL_TOR, "", false, false);
    public static final TorSandboxStatus DISABLED = new TorSandboxStatus(State.DISABLED, "", false, false);

    private final State state;
    // The level of the sandbox policy which sandy selected for this host, empty without the sandbox
    private final String level;
    // In the sandbox, Tor uses the network of the host, because this system cannot give it one of its own (Linux
    // where user namespaces are restricted or turned off), or because its pluggable transports need it.
    private final boolean hostNetwork;
    // In the sandbox, Tor can send signals to every process of the user, because the host cannot isolate them (Linux
    // before 6.12 without user namespaces).
    private final boolean signalsNotIsolated;

    private TorSandboxStatus(State state, String level, boolean hostNetwork, boolean signalsNotIsolated) {
        this.state = state;
        this.level = level;
        this.hostNetwork = hostNetwork;
        this.signalsNotIsolated = signalsNotIsolated;
    }

    /**
     * @param level            the level of the policy that sandy selected
     * @param privateNetwork   sandy gives Tor a network of its own in this level
     * @param signalsIsolated  sandy keeps the signals of Tor inside the sandbox in this level
     */
    public static TorSandboxStatus sandboxed(String level, boolean privateNetwork, boolean signalsIsolated) {
        return new TorSandboxStatus(State.SANDBOXED, level, !privateNetwork, !signalsIsolated);
    }

    public boolean isSandboxed() {
        return state == State.SANDBOXED;
    }

    // A text for the log and the user
    public String getDescription() {
        return switch (state) {
            case NOT_STARTED -> "Tor was not started yet.";
            case SANDBOXED -> "Tor runs in its sandbox." +
                    (hostNetwork ? " Tor uses the network of this computer, because this system cannot give it " +
                            "one of its own or because its pluggable transports need it, so Tor could reach the " +
                            "services of this computer and of the local network." : "") +
                    (signalsNotIsolated ? " This system cannot isolate the signals of Tor, so Tor could send " +
                            "signals to other processes of this user." : "");
            case EXTERNAL_TOR -> "Bisq uses a Tor which it did not start, so it cannot run that Tor in its sandbox. " +
                    "The protection of that Tor depends on how it runs.";
            case DISABLED -> "The Tor sandbox is turned off, so Tor runs with all rights of this user.";
        };
    }
}
