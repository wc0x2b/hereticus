package hereticus;

import java.util.Optional;

import ghidra.program.model.lang.Language;

/**
 * Which Ghidra languages hereticus reads, and the instruction set to give it
 * for a raw image of each.
 */
public final class Architectures {

	private Architectures() {
	}

	/**
	 * The instruction set hereticus reads a raw image of `language` as, or
	 * nothing where hereticus cannot read the language.
	 */
	public static Optional<InstructionSet> of(Language language) {
		return of(language.getProcessor().toString(), language.isBigEndian(),
			language.getLanguageDescription().getSize(),
			language.getLanguageDescription().getVariant());
	}

	/**
	 * The same, from the parts of a language ID, as `ARM:LE:32:Cortex`.
	 *
	 * A Cortex-M part runs only Thumb-2, so its raw image is Thumb-2. Another
	 * ARM image is read as A32, as `--arch` reads it by default.
	 */
	public static Optional<InstructionSet> of(String processor, boolean bigEndian, int size,
			String variant) {
		switch (processor) {
			case "ARM":
				if (bigEndian || size != 32) {
					return Optional.empty();
				}
				return Optional.of(
					variant.contains("Cortex") ? InstructionSet.THUMB2 : InstructionSet.ARM32);
			case "AARCH64":
				return bigEndian || size != 64 ? Optional.empty()
						: Optional.of(InstructionSet.AARCH64);
			case "MIPS":
				// The R6 and microMIPS variants encode other instructions.
				if (size != 32 || !variant.equals("default")) {
					return Optional.empty();
				}
				return Optional.of(bigEndian ? InstructionSet.MIPS32_BE : InstructionSet.MIPS32);
			default:
				return Optional.empty();
		}
	}
}
