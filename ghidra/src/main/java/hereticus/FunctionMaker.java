package hereticus;

import java.math.BigInteger;
import java.util.EnumMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Makes a Ghidra function at each start hereticus found that Ghidra did not.
 *
 * It changes nothing Ghidra already decided. A start inside a function Ghidra
 * made, on data Ghidra defined, or whose body would hold the start of a
 * function Ghidra made is left alone: the two disagree, and the analysis that
 * put the function or the data there may know better than a scan. A stripped
 * library shows why: a scan reads its whole PLT as one function, where Ghidra
 * marks up each entry.
 */
public final class FunctionMaker {

	/** What became of one start. */
	public enum Outcome {
		CREATED("made"),
		ALREADY_A_FUNCTION("already a function"),
		INSIDE_A_FUNCTION("inside a function Ghidra made"),
		HOLDS_A_FUNCTION("holding the start of a function Ghidra made"),
		ON_DATA("on data Ghidra defined"),
		HOLDS_DATA("a table or fill, not code"),
		NOT_IN_MEMORY("at no initialized address"),
		OUTSIDE_THE_SET("outside the addresses analyzed"),
		DOES_NOT_DECODE("does not decode as a function");

		private final String description;

		Outcome(String description) {
			this.description = description;
		}

		public String description() {
			return description;
		}
	}

	private final Program program;
	private final LinkedAddresses addresses;

	public FunctionMaker(Program program, LinkedAddresses addresses) {
		this.program = program;
		this.addresses = addresses;
	}

	/**
	 * Makes the functions of `listing` that start in `set`, and counts what
	 * became of each start.
	 */
	public Map<Outcome, Integer> make(FunctionListing listing, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		Map<Outcome, Integer> counts = new EnumMap<>(Outcome.class);
		monitor.initialize(listing.functions().size(), "Making the functions hereticus found");
		// From the highest address down. The body Ghidra gives a new function
		// stops at the start of another, but takes in code that a branch
		// reaches and no function starts at. A shared tail, as `__div0` that
		// each division routine branches to on a zero, comes after the
		// functions that reach it, and must be a function before they are.
		for (FunctionListing.Listed listed : listing.functions().reversed()) {
			monitor.increment();
			counts.merge(make(listed, set, monitor), 1, Integer::sum);
		}
		return counts;
	}

	/** Counts as one line for the analysis log, as `12 made, 3 already a function`. */
	public static String summary(Map<Outcome, Integer> counts) {
		return counts.entrySet()
				.stream()
				.map(entry -> entry.getValue() + " " + entry.getKey().description())
				.collect(Collectors.joining(", "));
	}

	private Outcome make(FunctionListing.Listed listed, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		if (listed.holds() != FunctionListing.Contents.CODE) {
			return Outcome.HOLDS_DATA;
		}
		Address entry = addresses.toProgram(listed.offset());
		if (entry == null) {
			return Outcome.NOT_IN_MEMORY;
		}
		if (!set.contains(entry)) {
			return Outcome.OUTSIDE_THE_SET;
		}
		FunctionManager functions = program.getFunctionManager();
		if (functions.getFunctionAt(entry) != null) {
			return Outcome.ALREADY_A_FUNCTION;
		}
		if (functions.getFunctionContaining(entry) != null) {
			return Outcome.INSIDE_A_FUNCTION;
		}
		if (holdsAnotherFunction(entry, listed.size())) {
			return Outcome.HOLDS_A_FUNCTION;
		}
		Listing code = program.getListing();
		if (code.getDefinedDataContaining(entry) != null) {
			return Outcome.ON_DATA;
		}
		if (code.getInstructionAt(entry) == null && !disassemble(entry, listed.isa(), monitor)) {
			return Outcome.DOES_NOT_DECODE;
		}
		boolean made = new CreateFunctionCmd(entry).applyTo(program, monitor);
		return made ? Outcome.CREATED : Outcome.DOES_NOT_DECODE;
	}

	/** Whether a function Ghidra made starts in the `size` bytes after `entry`. */
	private boolean holdsAnotherFunction(Address entry, long size) {
		if (size <= 1) {
			return false;
		}
		Address last;
		try {
			last = entry.addNoWrap(size - 1);
		}
		catch (AddressOverflowException e) {
			last = entry.getAddressSpace().getMaxAddress();
		}
		AddressSet body = new AddressSet(entry, last);
		for (Function function : program.getFunctionManager().getFunctions(body, true)) {
			if (!function.getEntryPoint().equals(entry)) {
				return true;
			}
		}
		return false;
	}

	/** Decodes the code from `entry` in `isa`, and says whether an instruction starts there. */
	private boolean disassemble(Address entry, InstructionSet isa, TaskMonitor monitor) {
		// An instruction that covers the entry from before it would be cut in two.
		if (program.getListing().getInstructionContaining(entry) != null) {
			return false;
		}
		DisassembleCommand command = new DisassembleCommand(entry, null, true);
		RegisterValue context = contextOf(isa);
		if (context != null) {
			command.setInitialContext(context);
		}
		command.applyTo(program, monitor);
		return program.getListing().getInstructionAt(entry) != null;
	}

	/** The context that makes Ghidra decode `isa`, where the language has one. */
	private RegisterValue contextOf(InstructionSet isa) {
		if (isa.contextRegister() == null) {
			return null;
		}
		Register register = program.getRegister(isa.contextRegister());
		if (register == null) {
			return null;
		}
		return new RegisterValue(register, BigInteger.valueOf(isa.contextValue()));
	}
}
