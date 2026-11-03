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

package bisq.network.tor.process;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Timeout(15)
class EmbeddedTorProcessShutdownTest {
    @Test
    void aChildThatIgnoresGracefulTerminationIsForciblyStopped() {
        ProcessHandle child = mock(ProcessHandle.class);
        CompletableFuture<ProcessHandle> exit = exitOf(child);
        when(child.destroyForcibly()).thenAnswer(invocation -> exit.complete(child));

        EmbeddedTorProcess.shutdownProcesses(List.of(child));

        assertThat(exit).isDone();
        verify(child).destroy();
        verify(child).destroyForcibly();
    }

    // On Windows, a terminated process reports its exit code before it has released its ports and files.
    @Test
    void aShutdownWaitsForTheEndOfAProcessWhichNoLongerReportsAlive() {
        ProcessHandle child = mock(ProcessHandle.class);
        CompletableFuture<ProcessHandle> exit = new CompletableFuture<>();
        when(child.onExit()).thenReturn(exit);
        when(child.isAlive()).thenReturn(true);
        when(child.destroy()).thenAnswer(invocation -> {
            when(child.isAlive()).thenReturn(false);
            CompletableFuture.delayedExecutor(200, TimeUnit.MILLISECONDS).execute(() -> exit.complete(child));
            return true;
        });

        EmbeddedTorProcess.shutdownProcesses(List.of(child));

        assertThat(exit).isDone();
    }

    @Test
    void aRemainingProcessFailsShutdownAndDoesNotPreventOtherProcessesFromBeingStopped() {
        ProcessHandle stubbornChild = mock(ProcessHandle.class);
        when(stubbornChild.pid()).thenReturn(123L);
        exitOf(stubbornChild);
        when(stubbornChild.destroy()).thenThrow(new SecurityException("Cannot signal the child"));
        when(stubbornChild.destroyForcibly()).thenThrow(new SecurityException("Cannot force the child"));
        ProcessHandle otherChild = mock(ProcessHandle.class);
        CompletableFuture<ProcessHandle> otherExit = exitOf(otherChild);
        when(otherChild.destroy()).thenAnswer(invocation -> otherExit.complete(otherChild));

        assertThatThrownBy(() -> EmbeddedTorProcess.shutdownProcesses(List.of(stubbornChild, otherChild)))
                .isInstanceOf(CouldNotWaitForTorShutdownException.class)
                .hasMessageContaining("123");

        assertThat(otherExit).isDone();
        verify(stubbornChild).destroyForcibly();
    }

    @Test
    void anInterruptedShutdownStopsTheChildAndRestoresTheInterrupt() throws Exception {
        ProcessHandle child = mock(ProcessHandle.class);
        CompletableFuture<ProcessHandle> exit = exitOf(child);
        CountDownLatch signalled = new CountDownLatch(1);
        when(child.destroy()).thenAnswer(invocation -> {
            signalled.countDown();
            return true;
        });
        when(child.destroyForcibly()).thenAnswer(invocation -> exit.complete(child));
        AtomicBoolean returnedWithInterrupt = new AtomicBoolean();
        Thread shutdown = new Thread(() -> {
            EmbeddedTorProcess.shutdownProcesses(List.of(child));
            returnedWithInterrupt.set(Thread.currentThread().isInterrupted());
        });
        shutdown.start();
        try {
            assertThat(signalled.await(5, TimeUnit.SECONDS)).isTrue();
            shutdown.interrupt();
            shutdown.join(5_000);

            assertThat(shutdown.isAlive()).isFalse();
            assertThat(exit).isDone();
            assertThat(returnedWithInterrupt).isTrue();
            verify(child).destroyForcibly();
        } finally {
            shutdown.interrupt();
            shutdown.join(5_000);
        }
    }

    // A process ends when its exit completes, as for a real ProcessHandle.
    private static CompletableFuture<ProcessHandle> exitOf(ProcessHandle process) {
        CompletableFuture<ProcessHandle> exit = new CompletableFuture<>();
        when(process.onExit()).thenReturn(exit);
        when(process.isAlive()).thenAnswer(invocation -> !exit.isDone());
        return exit;
    }
}
