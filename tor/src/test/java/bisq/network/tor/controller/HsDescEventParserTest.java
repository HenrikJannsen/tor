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

package bisq.network.tor.controller;

import bisq.network.tor.controller.events.events.HsDescEvent;
import bisq.network.tor.controller.events.events.HsDescFailedEvent;
import bisq.network.tor.controller.events.events.HsDescUploadEvent;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class HsDescEventParserTest {
    private static final String ADDRESS = "bedb3wpuybkuwvjat2zq5odtqbajq7x3ovllvh7l2kbxakbgkzgikqyd";
    private static final String HS_DIR = "$0123456789ABCDEF0123456789ABCDEF01234567~relay";

    @Test
    void parsesTheUploadEvents() {
        assertThat(parse("650 HS_DESC UPLOAD " + ADDRESS + " UNKNOWN " + HS_DIR + " descriptorId HSDIR_INDEX=index"))
                .map(HsDescEvent::getAction).contains(HsDescEvent.Action.UPLOAD);
        assertThat(parse("650 HS_DESC UPLOADED " + ADDRESS + " UNKNOWN " + HS_DIR))
                .map(HsDescEvent::getAction).contains(HsDescEvent.Action.UPLOADED);
    }

    @Test
    void acceptsFieldsWhichALaterTorAdds() {
        // The control-spec allows new fields at the end of an event. Otherwise the publication of an onion service
        // would never see the upload of its descriptor.
        Optional<HsDescEvent> upload = parse("650 HS_DESC UPLOAD " + ADDRESS + " UNKNOWN " + HS_DIR +
                " descriptorId HSDIR_INDEX=index NEWFIELD=value");
        assertThat(upload).map(HsDescEvent::getAction).contains(HsDescEvent.Action.UPLOAD);
        assertThat(upload).map(HsDescEvent::getHsAddress).contains(ADDRESS);
        assertThat(parse("650 HS_DESC UPLOADED " + ADDRESS + " UNKNOWN " + HS_DIR + " NEWFIELD=value"))
                .map(HsDescEvent::getAction).contains(HsDescEvent.Action.UPLOADED);
    }

    @Test
    void ignoresAnEventWithTooFewFields() {
        assertThat(parse("650 HS_DESC UPLOAD " + ADDRESS + " UNKNOWN")).isEmpty();
    }

    @Test
    void readsTheOptionalFieldsOfAFailure() {
        Optional<HsDescFailedEvent> complete = parseFailure("650 HS_DESC FAILED " + ADDRESS + " NO_AUTH " + HS_DIR +
                " descriptorId REASON=NOT_FOUND");
        assertThat(complete).flatMap(HsDescFailedEvent::getDescriptorId).contains("descriptorId");
        assertThat(complete).flatMap(HsDescFailedEvent::getReason).contains("NOT_FOUND");

        // The control-spec makes the descriptor ID and the reason optional.
        Optional<HsDescFailedEvent> withoutDescriptorId = parseFailure("650 HS_DESC FAILED " + ADDRESS + " NO_AUTH " +
                HS_DIR + " REASON=NOT_FOUND");
        assertThat(withoutDescriptorId).map(HsDescEvent::getHsAddress).contains(ADDRESS);
        assertThat(withoutDescriptorId.flatMap(HsDescFailedEvent::getDescriptorId)).isEmpty();
        assertThat(withoutDescriptorId).flatMap(HsDescFailedEvent::getReason).contains("NOT_FOUND");

        Optional<HsDescFailedEvent> withoutReason = parseFailure("650 HS_DESC FAILED " + ADDRESS + " NO_AUTH " + HS_DIR);
        assertThat(withoutReason).isPresent();
        assertThat(withoutReason.flatMap(HsDescFailedEvent::getReason)).isEmpty();

        // Another keyword where the descriptor ID could be is neither the descriptor ID nor the reason.
        Optional<HsDescFailedEvent> withOtherKeywords = parseFailure("650 HS_DESC FAILED " + ADDRESS + " NO_AUTH " +
                HS_DIR + " REPLICA=1 NEWFIELD=value REASON=QUERY_RATE_LIMITED");
        assertThat(withOtherKeywords.flatMap(HsDescFailedEvent::getDescriptorId)).isEmpty();
        assertThat(withOtherKeywords).flatMap(HsDescFailedEvent::getReason).contains("QUERY_RATE_LIMITED");
    }

    @Test
    void readsTheOptionalFieldsOfAnUploadAndAReceipt() {
        Optional<HsDescEvent> uploadWithoutIndex = parse("650 HS_DESC UPLOAD " + ADDRESS + " UNKNOWN " + HS_DIR +
                " descriptorId");
        assertThat(uploadWithoutIndex).map(HsDescEvent::getAction).contains(HsDescEvent.Action.UPLOAD);
        assertThat(uploadWithoutIndex.map(HsDescUploadEvent.class::cast).flatMap(HsDescUploadEvent::getHsDirIndex))
                .isEmpty();
        assertThat(parse("650 HS_DESC UPLOAD " + ADDRESS + " UNKNOWN " + HS_DIR + " descriptorId HSDIR_INDEX=index")
                .map(HsDescUploadEvent.class::cast)
                .flatMap(HsDescUploadEvent::getHsDirIndex))
                .contains("index");

        assertThat(parse("650 HS_DESC RECEIVED " + ADDRESS + " NO_AUTH " + HS_DIR))
                .map(HsDescEvent::getAction).contains(HsDescEvent.Action.RECEIVED);
    }

    @Test
    void ignoresAnActionWhichBisqDoesNotHandle() {
        assertThat(parse("650 HS_DESC REQUESTED " + ADDRESS + " NO_AUTH " + HS_DIR + " descriptorId")).isEmpty();
    }

    private static Optional<HsDescFailedEvent> parseFailure(String line) {
        Optional<HsDescEvent> event = parse(line);
        assertThat(event).map(HsDescEvent::getAction).contains(HsDescEvent.Action.FAILED);
        return event.map(HsDescFailedEvent.class::cast);
    }

    private static Optional<HsDescEvent> parse(String line) {
        return HsDescEventParser.tryParse(line.split(" "));
    }
}
