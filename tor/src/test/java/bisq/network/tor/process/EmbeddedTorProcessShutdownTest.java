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
        AtomicBoolean alive = new AtomicBoolean(true);
        when(child.isAlive()).thenAnswer(invocation -> alive.get());
        when(child.destroyForcibly()).thenAnswer(invocation -> {
            alive.set(false);
            return true;
        });

        EmbeddedTorProcess.shutdownProcesses(List.of(child));

        assertThat(alive).isFalse();
        verify(child).destroy();
        verify(child).destroyForcibly();
    }

    @Test
    void aRemainingProcessFailsShutdownAndDoesNotPreventOtherProcessesFromBeingStopped() {
        ProcessHandle stubbornChild = mock(ProcessHandle.class);
        when(stubbornChild.pid()).thenReturn(123L);
        when(stubbornChild.isAlive()).thenReturn(true);
        when(stubbornChild.destroy()).thenThrow(new SecurityException("Cannot signal the child"));
        when(stubbornChild.destroyForcibly()).thenThrow(new SecurityException("Cannot force the child"));
        ProcessHandle otherChild = mock(ProcessHandle.class);
        AtomicBoolean otherAlive = new AtomicBoolean(true);
        when(otherChild.isAlive()).thenAnswer(invocation -> otherAlive.get());
        when(otherChild.destroy()).thenAnswer(invocation -> {
            otherAlive.set(false);
            return true;
        });

        assertThatThrownBy(() -> EmbeddedTorProcess.shutdownProcesses(List.of(stubbornChild, otherChild)))
                .isInstanceOf(CouldNotWaitForTorShutdownException.class)
                .hasMessageContaining("123");

        assertThat(otherAlive).isFalse();
        verify(stubbornChild).destroyForcibly();
    }

    @Test
    void anInterruptedShutdownStopsTheChildAndRestoresTheInterrupt() throws Exception {
        ProcessHandle child = mock(ProcessHandle.class);
        AtomicBoolean alive = new AtomicBoolean(true);
        CountDownLatch signalled = new CountDownLatch(1);
        when(child.isAlive()).thenAnswer(invocation -> alive.get());
        when(child.destroy()).thenAnswer(invocation -> {
            signalled.countDown();
            return true;
        });
        when(child.destroyForcibly()).thenAnswer(invocation -> {
            alive.set(false);
            return true;
        });
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
            assertThat(alive).isFalse();
            assertThat(returnedWithInterrupt).isTrue();
            verify(child).destroyForcibly();
        } finally {
            shutdown.interrupt();
            shutdown.join(5_000);
        }
    }
}
