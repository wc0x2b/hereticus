package hereticus;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.OptionalLong;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * What `hereticus --find-base --format json` prints: the base a raw image
 * loads at, where one stands out.
 *
 * @param base the base, a number up to 2^64, or null where no base stands out
 */
public record BaseSearch(BigInteger base) {

	/** The arguments that find the base of the raw image at `image`. */
	public static List<String> arguments(InstructionSet isa, Path image) {
		return List.of("--raw", "--find-base", "--arch", isa.archName(), "--format", "json",
			image.toString());
	}

	/**
	 * Runs `tool` on the raw image at `image`, read as `isa`.
	 *
	 * @return the base as Ghidra keeps an offset, or nothing where no base
	 *         stands out
	 * @throws HereticusException if the tool fails or prints what is not its JSON
	 * @throws CancelledException if the user cancelled the run
	 */
	public static OptionalLong find(HereticusTool tool, InstructionSet isa, Path image,
			TaskMonitor monitor) throws HereticusException, CancelledException {
		return parse(tool.run(arguments(isa, image), monitor)).offset();
	}

	/**
	 * Reads what `hereticus --find-base --format json` printed.
	 *
	 * @throws HereticusException if the text is not such a result
	 */
	public static BaseSearch parse(String json) throws HereticusException {
		return Json.parse(json, BaseSearch.class);
	}

	/**
	 * The base as Ghidra keeps an offset: the same 64 bits, read as a signed
	 * number, or nothing where no base stands out.
	 */
	public OptionalLong offset() {
		return base == null ? OptionalLong.empty() : OptionalLong.of(base.longValue());
	}
}
