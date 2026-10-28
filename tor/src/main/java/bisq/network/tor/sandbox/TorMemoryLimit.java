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

import com.google.common.annotations.VisibleForTesting;
import lombok.extern.slf4j.Slf4j;

import java.lang.management.ManagementFactory;
import java.util.OptionalLong;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * The default of Tor's {@code MaxMemInQueues}, which Bisq writes into the torrc of a sandboxed Tor. Tor derives it from
 * the size of the memory, which a sandboxed Tor cannot always read: on Linux it reads {@code /proc/meminfo}, which the
 * sandbox does not grant, and without it Tor assumes 8 GB. With the value in the torrc, the sandbox does not change
 * the limit.
 */
@Slf4j
public final class TorMemoryLimit {
    private static final long ONE_GIGABYTE = 1L << 30;
    private static final long VERY_LARGE_MEMORY_SIZE = 8 * ONE_GIGABYTE;
    private static final long MIN_DEFAULT = ONE_GIGABYTE / 4;
    private static final long MAX_DEFAULT = 8 * ONE_GIGABYTE;
    @VisibleForTesting
    static final String UNKNOWN_MEMORY_SIZE_TORRC_VALUE = "512 MB";

    private TorMemoryLimit() {
    }

    /**
     * @return the default of {@code MaxMemInQueues} for the memory of this system as a torrc value, or 512 MB if the
     * size of the memory is unknown
     */
    public static String torrcValue() {
        return torrcValue(findTotalMemorySize());
    }

    @VisibleForTesting
    static String torrcValue(OptionalLong totalMemorySize) {
        if (totalMemorySize.isEmpty()) {
            log.info("The size of the memory is unknown, so Tor gets MaxMemInQueues {}",
                    UNKNOWN_MEMORY_SIZE_TORRC_VALUE);
            return UNKNOWN_MEMORY_SIZE_TORRC_VALUE;
        }
        return defaultMaxMemInQueues(totalMemorySize.getAsLong()) + " bytes";
    }

    /**
     * As Tor 0.4.9 computes it on a 64-bit system ({@code compute_real_max_mem_in_queues} in
     * {@code src/app/config/config.c}), dividing before it multiplies.
     */
    @VisibleForTesting
    static long defaultMaxMemInQueues(long totalMemorySize) {
        checkArgument(totalMemorySize > 0, "Invalid memory size: " + totalMemorySize);
        long available = totalMemorySize >= VERY_LARGE_MEMORY_SIZE
                ? (totalMemorySize / 5) * 2
                : (totalMemorySize / 4) * 3;
        return Math.min(MAX_DEFAULT, Math.max(MIN_DEFAULT, available));
    }

    // The JVM reports the memory limit of a container if one applies, else the memory of the system.
    private static OptionalLong findTotalMemorySize() {
        try {
            if (ManagementFactory.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean bean) {
                long totalMemorySize = bean.getTotalMemorySize();
                if (totalMemorySize > 0) {
                    return OptionalLong.of(totalMemorySize);
                }
            }
        } catch (LinkageError | RuntimeException e) {
            // A runtime without java.lang.management or com.sun.management, such as Android
            log.warn("Cannot read the size of the memory", e);
        }
        return OptionalLong.empty();
    }
}
