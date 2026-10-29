package bisq.network.tor.controller;

/**
 * The control port answered a command with "510 Command filtered". Tor itself does not filter commands; a filter in
 * front of Tor does, such as onion-grater on the Whonix-Gateway.
 */
public class TorCommandFilteredException extends RuntimeException {
    /**
     * @param isWhonix Bisq runs on a Whonix-Workstation, whose Gateway filters the control port with onion-grater
     */
    public TorCommandFilteredException(String commandName, boolean isWhonix) {
        super(createMessage(commandName, isWhonix));
    }

    static String createMessage(String commandName, boolean isWhonix) {
        String message = "The control port does not allow the command " + commandName +
                " (510 Command filtered). A filter in front of Tor refused it.";
        return isWhonix ?
                message + " On the Whonix-Gateway, update the system and enable the onion-grater profile of Bisq with " +
                        "\"sudo onion-grater-add 40_bisq\"." :
                message;
    }
}
