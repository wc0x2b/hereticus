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

	private static final Map<String, Double> BY_STAGE = Map.ofEntries(
		Map.entry("identical bytes", 10.0),
		Map.entry("identical shape", 9.0),
		Map.entry("same name", 8.0),
		Map.entry("twin, by the text in its row", 7.5),
		Map.entry("twin, by the class of its vtable", 7.25),
		Map.entry("twin, in order", 7.0),
		Map.entry("same slot of a table", 6.0),
		Map.entry("same import", 6.0),
		Map.entry("same references", 5.0),
		Map.entry("same callers", 4.0),
		Map.entry("same place", 3.0),
		Map.entry("similar", 2.0));

	private Confidence() {
	}

	/** The confidence for a pair the stage `matchedBy` made. */
	static double of(String matchedBy) {
		return BY_STAGE.getOrDefault(matchedBy, UNKNOWN);
	}
}
