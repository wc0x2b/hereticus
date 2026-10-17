package hereticus;

import com.google.gson.annotations.SerializedName;

/**
 * The instruction sets hereticus reads, as `--arch` names them.
 *
 * ARM and MIPS each have two sets in one processor. Ghidra keeps which set an
 * address holds in a context register, so a function in the minority set must
 * set that register before Ghidra decodes it.
 */
public enum InstructionSet {
	@SerializedName("arm32")
	ARM32("arm32", "TMode", 0),
	@SerializedName("thumb2")
	THUMB2("thumb2", "TMode", 1),
	@SerializedName("aarch64")
	AARCH64("aarch64", null, 0),
	@SerializedName("mips32")
	MIPS32("mips32", "ISA_MODE", 0),
	@SerializedName("mips32-be")
	MIPS32_BE("mips32-be", "ISA_MODE", 0),
	@SerializedName("mips16")
	MIPS16("mips16", "ISA_MODE", 1),
	@SerializedName("mips16-be")
	MIPS16_BE("mips16-be", "ISA_MODE", 1);

	private final String archName;
	private final String contextRegister;
	private final int contextValue;

	InstructionSet(String archName, String contextRegister, int contextValue) {
		this.archName = archName;
		this.contextRegister = contextRegister;
		this.contextValue = contextValue;
	}

	/** The name `--arch` takes. */
	public String archName() {
		return archName;
	}

	/** The Ghidra context register that selects this set, or null for none. */
	public String contextRegister() {
		return contextRegister;
	}

	/** The value of {@link #contextRegister()} that selects this set. */
	public int contextValue() {
		return contextValue;
	}
}
