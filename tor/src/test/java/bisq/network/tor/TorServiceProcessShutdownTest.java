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

import bisq.network.tor.controller.TorController;
import bisq.network.tor.process.CouldNotWaitForTorShutdownException;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@Timeout(15)
class TorServiceProcessShutdownTest {
    @TempDir
    Path torDir;

    @Test
    void theTreeIsCapturedBeforeControllerClosureEvenWhenTheControllerFails() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        TorController controller = mock(TorController.class);
        doThrow(new IllegalStateException("Controller shutdown failed")).when(controller).shutdown();
        TorService service = serviceWithManagedProcess(process, controller);

        assertThat(service.shutdown().get(10, TimeUnit.SECONDS)).isTrue();

        var order = inOrder(process, controller);
        for (int attempt = 0; attempt < 2; attempt++) {
            order.verify(process).captureProcessTree();
            order.verify(controller).shutdown();
            order.verify(process).shutdown();
        }
    }

    @Test
    void remainingProcessesFailTheShutdownFuture() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        var failure = new CouldNotWaitForTorShutdownException("Tor processes still run");
        doThrow(failure).when(process).shutdown();
        TorService service = serviceWithManagedProcess(process, mock(TorController.class));

        assertThatThrownBy(() -> service.shutdown().get(10, TimeUnit.SECONDS)).hasCause(failure);

        verify(process, times(2)).shutdown();
    }

    @Test
    void aSuccessfulFinalAttemptAllowsShutdownToComplete() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        doThrow(new CouldNotWaitForTorShutdownException("Initial termination failed"))
                .doNothing().when(process).shutdown();
        TorService service = serviceWithManagedProcess(process, mock(TorController.class));

        assertThat(service.shutdown().get(10, TimeUnit.SECONDS)).isTrue();

        verify(process, times(2)).shutdown();
    }

    // Bisq 2 shows the root cause of a failed start, so a failed stop must not take its place.
    @Test
    void aFailedStopAfterAFailedStartKeepsTheFailureOfTheStart() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        TorController controller = mock(TorController.class);
        var stopFailure = new CouldNotWaitForTorShutdownException("Tor processes still run");
        doThrow(stopFailure).when(process).shutdown();
        TorService service = serviceWithManagedProcess(process, controller);
        var startFailure = new TorStartupFailedException("Tor exited during bootstrap");

        assertThat(service.stopEmbeddedTorAfterFailedStart(process, startFailure)).isSameAs(startFailure);

        assertThat(startFailure.getSuppressed()).containsExactly(stopFailure);
        var order = inOrder(process, controller);
        order.verify(process).captureProcessTree();
        order.verify(controller).shutdown();
        order.verify(process).shutdown();
        // The remaining processes are stopped again and reported by the shutdown.
        assertThatThrownBy(() -> service.shutdown().get(10, TimeUnit.SECONDS)).hasCause(stopFailure);
        verify(process, times(3)).shutdown();
    }

    // A refusal of sandy starts a second attempt only if the failed stop does not replace it.
    @Test
    void aFailedStopAfterARefusalOfSandyStillStartsASecondAttempt() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        doThrow(new CouldNotWaitForTorShutdownException("Tor processes still run")).when(process).shutdown();
        TorService service = serviceWithManagedProcess(process, mock(TorController.class));
        var attempts = new AtomicInteger();

        TorService.retryOnceAfterARefusalOfSandy(() -> {
            if (attempts.incrementAndGet() == 1) {
                throw service.stopEmbeddedTorAfterFailedStart(process,
                        new TorService.SandyRefusalException("sandy: run failed", "hint"));
            }
        });

        assertThat(attempts).hasValue(2);
    }

    @Test
    void aSuccessfulStopAfterAFailedStartForgetsTheProcess() throws Exception {
        EmbeddedTorProcess process = mock(EmbeddedTorProcess.class);
        TorService service = serviceWithManagedProcess(process, mock(TorController.class));
        var startFailure = new TorStartupFailedException("Tor exited during bootstrap");

        assertThat(service.stopEmbeddedTorAfterFailedStart(process, startFailure)).isSameAs(startFailure);

        assertThat(startFailure.getSuppressed()).isEmpty();
        assertThat(service.shutdown().get(10, TimeUnit.SECONDS)).isTrue();
        verify(process, times(1)).shutdown();
    }

    private TorService serviceWithManagedProcess(EmbeddedTorProcess process, TorController controller) throws Exception {
        var config = new TorTransportConfig(torDir, 10_000, 10_000, false, Set.of(), Map.of(), false);
        var service = new TorService(config, mock(PlatformServices.class), false);
        // Install only the shutdown dependencies; these tests run on Windows too and start no Tor or shell.
        var processField = TorService.class.getDeclaredField("torProcess");
        processField.setAccessible(true);
        processField.set(service, Optional.of(process));
        var controllerField = TorService.class.getDeclaredField("torController");
        controllerField.setAccessible(true);
        controllerField.set(service, controller);
        return service;
    }
}
