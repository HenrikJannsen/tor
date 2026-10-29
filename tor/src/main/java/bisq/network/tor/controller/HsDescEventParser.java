package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.*;

import java.util.Arrays;
import java.util.Optional;

public class HsDescEventParser {
    // 650 HS_DESC Action HSAddress AuthType HsDir [DescriptorID] [REASON=Reason] [REPLICA=Replica]
    // [HSDIR_INDEX=HSDirIndex] (control-spec). The fields in brackets are optional, and a later Tor can add more.
    private static final int NUM_FIXED_FIELDS = 6;
    private static final String REASON_KEY = "REASON=";
    private static final String HSDIR_INDEX_KEY = "HSDIR_INDEX=";

    public static Optional<HsDescEvent> tryParse(String[] parts) {
        if (parts.length < NUM_FIXED_FIELDS) {
            return Optional.empty();
        }
        Optional<HsDescEvent.Action> action = Arrays.stream(HsDescEvent.Action.values())
                .filter(candidate -> candidate.name().equals(parts[2]))
                .findFirst();
        if (action.isEmpty()) {
            return Optional.empty();
        }
        String hsAddress = parts[3];
        String authType = parts[4];
        String hsDir = parts[5];
        // The descriptor ID is the only optional field without a keyword, and it comes first.
        Optional<String> descriptorId = parts.length > NUM_FIXED_FIELDS && !parts[NUM_FIXED_FIELDS].contains("=") ?
                Optional.of(parts[NUM_FIXED_FIELDS]) :
                Optional.empty();

        HsDescEvent hsDescEvent = switch (action.get()) {
            case CREATED, RECEIVED -> HsDescCreatedOrReceivedEvent.builder()
                    .action(action.get())
                    .hsAddress(hsAddress)
                    .authType(authType)
                    .hsDir(hsDir)
                    .descriptorId(descriptorId)
                    .build();
            case UPLOAD -> HsDescUploadEvent.builder()
                    .action(action.get())
                    .hsAddress(hsAddress)
                    .authType(authType)
                    .hsDir(hsDir)
                    .descriptorId(descriptorId)
                    .hsDirIndex(findValue(parts, HSDIR_INDEX_KEY))
                    .build();
            case UPLOADED -> HsDescUploadedEventV2.builder()
                    .action(action.get())
                    .hsAddress(hsAddress)
                    .authType(authType)
                    .hsDir(hsDir)
                    .build();
            case FAILED -> HsDescFailedEvent.builder()
                    .action(action.get())
                    .hsAddress(hsAddress)
                    .authType(authType)
                    .hsDir(hsDir)
                    .descriptorId(descriptorId)
                    .reason(findValue(parts, REASON_KEY))
                    .build();
        };
        return Optional.of(hsDescEvent);
    }

    // The value of the optional field with the keyword, wherever it is after the fixed fields
    private static Optional<String> findValue(String[] parts, String key) {
        return Arrays.stream(parts, NUM_FIXED_FIELDS, parts.length)
                .filter(part -> part.startsWith(key))
                .map(part -> part.substring(key.length()))
                .findFirst();
    }
}
