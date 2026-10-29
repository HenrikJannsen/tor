package bisq.network.tor.controller.events.events;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.Optional;

@SuperBuilder
@Getter
@ToString(callSuper = true)
public class HsDescUploadEvent extends HsDescCreatedOrReceivedEvent {
    // Optional in the control-spec
    @Builder.Default
    private final Optional<String> hsDirIndex = Optional.empty();
}
