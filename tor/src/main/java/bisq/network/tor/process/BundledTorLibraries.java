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

import bisq.network.tor.common.platform.OS;
import com.google.common.annotations.VisibleForTesting;

import java.nio.file.Path;
import java.util.Map;

/**
 * How the bundled tor finds its libraries. The tor of the Linux bundle has no RUNPATH, so the loader finds libevent,
 * libssl and libcrypto of the bundle only through {@code LD_LIBRARY_PATH}, which names the binary directory. The loader
 * then takes from there only the libraries which tor needs, so another file in that directory is never loaded. The
 * bundles of macOS and Windows need no variable.
 */
public final class BundledTorLibraries {
    static final String LD_LIBRARY_PATH = "LD_LIBRARY_PATH";

    private BundledTorLibraries() {
    }

    /**
     * The variables for the libraries of the bundle, the whole environment which a sandboxed Tor gets for them.
     *
     * @throws TorStartupFailedException if the loader cannot take the binary directory from LD_LIBRARY_PATH
     */
    public static Map<String, String> environment(Path binaryDirPath) {
        return environment(binaryDirPath, OS.isLinux());
    }

    /**
     * Prepares the environment of a Tor without the sandbox, which starts with the environment of Bisq. Every loader
     * variable of Bisq's environment is removed, so that it loads no code into Tor.
     *
     * @throws TorStartupFailedException if the loader cannot take the binary directory from LD_LIBRARY_PATH
     */
    public static void applyToEnvironment(Map<String, String> environment, Path binaryDirPath) {
        applyToEnvironment(environment, binaryDirPath, OS.isLinux());
    }

    @VisibleForTesting
    static Map<String, String> environment(Path binaryDirPath, boolean isLinux) {
        if (!isLinux) {
            return Map.of();
        }
        String path = binaryDirPath.toAbsolutePath().toString();
        // The loader splits LD_LIBRARY_PATH at ":" and ";", and searches a part which is not absolute relative to the
        // working directory of Tor, which in the sandbox is the data directory that Tor can write.
        if (path.contains(":") || path.contains(";")) {
            throw new TorStartupFailedException("Tor cannot load its libraries from " + path + ", because the path " +
                    "contains \":\" or \";\". Choose a data directory for Bisq without these characters.");
        }
        return Map.of(LD_LIBRARY_PATH, path);
    }

    @VisibleForTesting
    static void applyToEnvironment(Map<String, String> environment, Path binaryDirPath, boolean isLinux) {
        Map<String, String> libraryEnvironment = environment(binaryDirPath, isLinux);
        environment.keySet().removeIf(name -> name.startsWith("LD_"));
        environment.putAll(libraryEnvironment);
    }
}
