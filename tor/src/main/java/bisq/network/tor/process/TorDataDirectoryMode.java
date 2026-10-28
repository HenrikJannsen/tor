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

import bisq.network.tor.common.file.FileUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * Records whether the last Tor which used the data directory ran in the sandbox, in a file of the Tor directory which a
 * sandboxed Tor cannot write ({@link TorDirectories#getDataModePath()}).
 * <p>
 * A Tor which an attacker compromised in its sandbox can leave files in the data directory, the only path it may
 * write, which exploit the next Tor that parses them, such as the cached directory documents or the state file. A Tor
 * without the sandbox has all rights of the user, so before it starts on a data directory which a sandboxed Tor may
 * have written, the directory is cleared. A Tor in the sandbox may parse what a Tor without it wrote, because it is
 * confined either way, so a start in the sandbox keeps the data directory.
 */
public final class TorDataDirectoryMode {
    private static final String SANDBOXED = "sandboxed";
    private static final String UNSANDBOXED = "unsandboxed";

    private TorDataDirectoryMode() {
    }

    /**
     * Records the sandbox before a sandboxed Tor runs. Without the record, a later start without the sandbox would keep
     * what this Tor writes, so the caller must not start Tor if this fails.
     */
    public static void recordSandboxed(TorDirectories directories,
                                       boolean posixPermissionsAllowed) throws IOException {
        write(directories, SANDBOXED, posixPermissionsAllowed);
    }

    /**
     * Clears the data directory before a Tor without the sandbox runs, unless the record shows that a Tor without the
     * sandbox used it last, and then records that. A missing or unreadable record counts as a sandboxed Tor, because a
     * version of the library before the record may have run Tor in the sandbox.
     *
     * @param isNewDataDirectory the data directory did not exist before this start prepared it. It then holds nothing,
     *                           or the state of Tor which the migration moved from the layout before the sandbox,
     *                           which no sandboxed Tor wrote.
     * @return whether the data directory was cleared
     */
    public static boolean prepareWithoutSandbox(TorDirectories directories,
                                                boolean isNewDataDirectory,
                                                boolean posixPermissionsAllowed) throws IOException {
        boolean clear = !isNewDataDirectory && !isUnsandboxed(directories.getDataModePath());
        if (clear) {
            // The deletion assumes that no process writes the directory. A Tor of an earlier start which still runs on
            // it, which only a level without end_with_parent allows after Bisq crashed, could make it follow a link.
            Path dataDirPath = directories.getDataDirPath();
            FileUtils.deleteRecursively(dataDirPath);
            FileUtils.createDirectories(dataDirPath, posixPermissionsAllowed);
        }
        write(directories, UNSANDBOXED, posixPermissionsAllowed);
        return clear;
    }

    private static boolean isUnsandboxed(Path modePath) {
        try {
            return Files.isRegularFile(modePath, LinkOption.NOFOLLOW_LINKS) &&
                    FileUtils.readUTF8String(modePath).trim().equals(UNSANDBOXED);
        } catch (IOException e) {
            return false;
        }
    }

    private static void write(TorDirectories directories, String mode, boolean posixPermissionsAllowed)
            throws IOException {
        FileUtils.writeToPath(mode + "\n", directories.getDataModePath(), posixPermissionsAllowed);
    }
}
