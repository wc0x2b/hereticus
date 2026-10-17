package hereticus;

import java.util.Map;

/**
 * The confidence score of Version Tracking for what paired two functions.
 *
 * The similarity score says how alike two functions are. The confidence says
 * how sure the pairing is: a function paired by identical bytes is surer than
 * one paired because it is the most similar left. The order is the order of
 * the stages of hereticus, the surest first.
 */
final class Confidence {

	/** The confidence of a stage this extension does not know, as a newer hereticus adds. */
	static final double UNKNOWN = 1.0;

	private static final Map<String, Double> BY_STAGE = Map.of(
		"identical bytes", 10.0,
		"identical shape", 9.0,
		"same name", 8.0,
		"twin, in order", 7.0,
		"same slot of a table", 6.0,
		"same import", 6.0,
		"same references", 5.0,
		"same callers", 4.0,
		"same place", 3.0,
		"similar", 2.0);

	private Confidence() {
	}

	/** The confidence for a pair the stage `matchedBy` made. */
	static double of(String matchedBy) {
		return BY_STAGE.getOrDefault(matchedBy, UNKNOWN);
	}
}
