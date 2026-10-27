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

/**
 * Bisq did not start Tor because the sandbox cannot be enforced. The message explains the reason and how a user can
 * turn the sandbox off, which depends on the application.
 */
public class SandboxUnavailableException extends RuntimeException {
    /**
     * @param optOutHint how the user of the application turns the sandbox off, for example "Start Bisq with the
     *                   option --useTorSandbox=false"
     */
    public SandboxUnavailableException(String reason, String optOutHint) {
        super(createMessage(reason, optOutHint));
    }

    public SandboxUnavailableException(String reason, String optOutHint, Throwable cause) {
        super(createMessage(reason, optOutHint), cause);
    }

    private static String createMessage(String reason, String optOutHint) {
        return "Bisq did not start Tor, because it cannot run Tor in its sandbox on this system.\n" +
                reason + "\n" +
                "Without the sandbox, a security bug in Tor gives an attacker access to all your files, including " +
                "your Bisq keys. " + optOutHint;
    }
}
