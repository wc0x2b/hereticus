package hereticus;

import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Moves an address between where a binary is linked, which hereticus reports,
 * and where Ghidra loaded it.
 *
 * Ghidra loads an ELF shared object linked at 0 at another base, such as
 * 0x10000, and a user can move any program to another base. Each address
 * moves by the same amount.
 */
public final class LinkedAddresses {

	private final Program program;
	/** The address in the program, less the linked address. */
	private final long shift;

	private LinkedAddresses(Program program, long shift) {
		this.program = program;
		this.shift = shift;
	}

	/**
	 * The addresses of `program`, read as `file` gives it to hereticus.
	 *
	 * A raw image is given at the base Ghidra loaded it at, so its addresses
	 * do not move.
	 */
	public static LinkedAddresses of(Program program, ProgramFile file) {
		if (file.kind() == ProgramFile.Kind.RAW) {
			return new LinkedAddresses(program, 0);
		}
		Long linkedBase = ElfLoader.getElfOriginalImageBase(program);
		long loadedBase = program.getImageBase().getOffset();
		return new LinkedAddresses(program, shift(loadedBase, linkedBase));
	}

	/**
	 * How far the program moved from where it is linked. Without the base the
	 * ELF loader records, it did not move.
	 */
	static long shift(long loadedBase, Long linkedBase) {
		return linkedBase == null ? 0 : loadedBase - linkedBase;
	}

	/**
	 * The address in the program of the linked address `linked`, or null where
	 * the program holds no initialized bytes there.
	 */
	public Address toProgram(long linked) {
		Address address;
		try {
			address = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(linked + shift);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(address);
		return block != null && block.isInitialized() ? address : null;
	}

	/** The linked address of `address`, an address in the program. */
	public long toLinked(Address address) {
		return address.getOffset() - shift;
	}
}
