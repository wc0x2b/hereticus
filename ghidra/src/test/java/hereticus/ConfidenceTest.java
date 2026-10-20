package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class ConfidenceTest {

	/** The stages of hereticus, the surest first, as the CLI names them. */
	private static final List<String> STAGES = List.of("identical bytes", "identical shape",
		"same name", "twin, by the text in its row", "twin, in order", "same slot of a table", "same references",
		"same callers", "same place", "similar");

	@Test
	void aSurerStageIsMoreConfident() {
		for (int index = 1; index < STAGES.size(); index++) {
			assertTrue(Confidence.of(STAGES.get(index - 1)) > Confidence.of(STAGES.get(index)),
				STAGES.get(index - 1) + " before " + STAGES.get(index));
		}
	}

	@Test
	void anUnknownStageIsTheLeastConfident() {
		assertEquals(Confidence.UNKNOWN, Confidence.of("a stage of a newer hereticus"));
		for (String stage : STAGES) {
			assertTrue(Confidence.of(stage) > Confidence.UNKNOWN, stage);
		}
	}
}
