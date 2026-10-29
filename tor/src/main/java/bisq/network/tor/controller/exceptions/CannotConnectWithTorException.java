package bisq.network.tor.controller.exceptions;

public class CannotConnectWithTorException extends RuntimeException {
    public CannotConnectWithTorException(Throwable cause) {
        super(cause);
    }

    public CannotConnectWithTorException(String message) {
        super(message);
    }

    public CannotConnectWithTorException(String message, Throwable cause) {
        super(message, cause);
    }
}
