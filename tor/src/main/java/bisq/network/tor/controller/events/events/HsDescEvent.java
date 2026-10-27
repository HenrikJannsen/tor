package bisq.network.tor.controller.events.events;

import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Getter
@ToString
public abstract class HsDescEvent {
    // The actions which Bisq handles. The control-spec has more, for example REQUESTED, which the parser ignores.
    public enum Action {
        CREATED,
        FAILED,
        RECEIVED,
        UPLOAD,
        UPLOADED
    }

    protected final Action action;
    protected final String hsAddress;
    protected final String authType;
    protected final String hsDir;
}
