package hereticus;

import java.math.BigInteger;
import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 * What `hereticus --format json --all` prints, as far as Version Tracking
 * needs it: each pair of functions, at the addresses the binaries are linked
 * at.
 *
 * @param pairs each function of the earlier binary with the one of the later
 *        binary it became
 */
public record DiffReport(List<Pair> pairs) {

	/**
	 * One function of one side.
	 *
	 * @param name the symbol, or `sub_<hex>` where there is none
	 * @param address the linked address of the first instruction
	 */
	public record Side(String name, BigInteger address) {

		/** The address as Ghidra keeps an offset. See {@link FunctionListing.Listed#offset()}. */
		public long offset() {
			return address.longValue();
		}
	}

	/**
	 * One pair.
	 *
	 * @param before the function of the earlier binary
	 * @param after the function of the later binary
	 * @param change what changed, as the CHANGE column of the report says it,
	 *        such as `same` or `changed`
	 * @param score how alike the two are, from 0.0 to 1.0
	 * @param matchedBy what paired them, as the MATCHED BY column says it
	 */
	public record Pair(Side before, Side after, String change, double score,
			@SerializedName("matched_by") String matchedBy) {
	}

	/**
	 * Reads what `hereticus --format json` printed.
	 *
	 * @throws HereticusException if the text is not such a report
	 */
	public static DiffReport parse(String json) throws HereticusException {
		DiffReport report = Json.parse(json, DiffReport.class);
		for (Pair pair : Json.required(report.pairs(), "pairs")) {
			Json.required(pair, "pairs[]");
			Json.required(Json.required(pair.before(), "before").address(), "before.address");
			Json.required(Json.required(pair.after(), "after").address(), "after.address");
			Json.required(pair.change(), "change");
			Json.required(pair.matchedBy(), "matched_by");
		}
		return report;
	}
}
