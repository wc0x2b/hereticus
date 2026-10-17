package hereticus;

import java.math.BigInteger;
import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 * What `hereticus --functions --format json` prints: each function of one
 * binary, at the address the binary is linked at.
 *
 * @param isa the instruction set most of the functions are in
 * @param foundBy `symbols` where the symbol table named every function, or
 *        `scanning` where the code was scanned for them
 * @param functions each function, in address order
 */
public record FunctionListing(InstructionSet isa, @SerializedName("found_by") String foundBy,
		List<Listed> functions) {

	/** What one function holds. */
	public enum Contents {
		@SerializedName("code")
		CODE,
		/** A table or fill that a scan read as a function. */
		@SerializedName("data")
		DATA
	}

	/**
	 * One function.
	 *
	 * @param name the symbol, or `sub_<hex>` where there is none
	 * @param address the linked address of the first instruction; a number up
	 *        to 2^64, since an AArch64 kernel links at the top of memory
	 * @param size the size in bytes
	 * @param isa the instruction set the function is in
	 * @param holds code, or data that a scan read as a function
	 */
	public record Listed(String name, BigInteger address, long size, InstructionSet isa,
			Contents holds) {

		/**
		 * The address as Ghidra keeps an offset: the same 64 bits, read as a
		 * signed number.
		 */
		public long offset() {
			return address.longValue();
		}
	}

	/**
	 * Reads what `hereticus --functions --format json` printed.
	 *
	 * @throws HereticusException if the text is not such a listing
	 */
	public static FunctionListing parse(String json) throws HereticusException {
		FunctionListing listing = Json.parse(json, FunctionListing.class);
		for (Listed listed : Json.required(listing.functions(), "functions")) {
			Json.required(listed, "functions[]");
			Json.required(listed.address(), "address");
			Json.required(listed.isa(), "isa");
			Json.required(listed.holds(), "holds");
		}
		return listing;
	}
}
