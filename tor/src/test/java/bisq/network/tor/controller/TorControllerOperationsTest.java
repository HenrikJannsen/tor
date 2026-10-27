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

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * TorController runs at most one publication and one online check per onion address. A finished operation must leave
 * its map, also when it finishes before the caller could register anything, or every later call for the address would
 * get its old result until Tor restarts.
 */
class TorControllerOperationsTest {
    private static final String ONION_ADDRESS = "address.onion";

    private final Map<String, TorController.Operation<Boolean>> operations = new ConcurrentHashMap<>();

    @Test
    void anOperationWhichCompletesAtOnceLeavesTheMap() {
        CompletableFuture<Boolean> result = TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> CompletableFuture.completedFuture(true));

        assertThat(result).isCompletedWithValue(true);
        assertThat(operations).isEmpty();
    }

    @Test
    void anOperationWhichFailsToStartLeavesTheMap() {
        CompletableFuture<Boolean> result = TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> {
            throw new IllegalStateException("The start fails");
        });

        assertThatThrownBy(result::join).hasCauseInstanceOf(IllegalStateException.class);
        assertThat(operations).isEmpty();
    }

    @Test
    void aRunningOperationIsSharedAndAFinishedOneIsNot() {
        AtomicInteger starts = new AtomicInteger();
        CompletableFuture<Boolean> work = new CompletableFuture<>();
        CompletableFuture<Boolean> first = TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> {
            starts.incrementAndGet();
            return work;
        });
        CompletableFuture<Boolean> second = TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> {
            starts.incrementAndGet();
            return new CompletableFuture<>();
        });

        assertThat(second).isSameAs(first);
        assertThat(starts).hasValue(1);

        work.complete(false);
        assertThat(first).isCompletedWithValue(false);
        assertThat(operations).isEmpty();

        TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> {
            starts.incrementAndGet();
            return new CompletableFuture<>();
        });
        assertThat(starts).hasValue(2);
    }

    @Test
    void aKeptSuccessAnswersEveryLaterCallAndAFailureDoesNot() {
        // Tor keeps a published onion service until the connection ends, so a later publication must not send a
        // second ADD_ONION, which Tor would refuse.
        AtomicInteger starts = new AtomicInteger();
        CompletableFuture<Boolean> success = TorController.runOnce(operations, ONION_ADDRESS, true, () -> {
        }, () -> {
            starts.incrementAndGet();
            return CompletableFuture.completedFuture(true);
        });
        CompletableFuture<Boolean> later = TorController.runOnce(operations, ONION_ADDRESS, true, () -> {
        }, () -> {
            starts.incrementAndGet();
            return CompletableFuture.completedFuture(true);
        });

        assertThat(later).isSameAs(success).isCompletedWithValue(true);
        assertThat(starts).hasValue(1);

        String otherOnionAddress = "other.onion";
        TorController.runOnce(operations, otherOnionAddress, true, () -> {
        }, () -> CompletableFuture.failedFuture(new IllegalStateException("The work fails")));
        assertThat(operations).containsOnlyKeys(ONION_ADDRESS);
    }

    @Test
    void theOperationLeavesTheMapBeforeItsResultIsVisible() {
        // A caller which retries as soon as it sees the failure must start a new operation.
        CompletableFuture<Boolean> work = new CompletableFuture<>();
        CompletableFuture<Boolean> result = TorController.runOnce(operations, ONION_ADDRESS, false, () -> {
        }, () -> work);
        AtomicInteger operationsSeenByTheCaller = new AtomicInteger(-1);
        result.whenComplete((value, throwable) -> operationsSeenByTheCaller.set(operations.size()));

        work.completeExceptionally(new IllegalStateException("The work fails"));

        assertThat(operationsSeenByTheCaller).hasValue(0);
    }
}
