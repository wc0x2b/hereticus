// Run Ghidra Auto Version Tracking on two programs, and write the functions
// it finds changed, gone and new as JSON. Run by `fixtures/rivals.sh`.
//
// The current program is the destination, the newer side. The first argument
// names the source program in the same project, and the second the JSON file
// to write.
//
// Auto Version Tracking pairs the functions, but does not say which pairs
// changed. `FindChangedFunctionsScript`, which ships with Ghidra, calls a
// function changed when no "Exact Function Instructions Match" pairs it.
// This script uses the same rule, and also counts the other correlators that
// pair only identical instructions as unchanged. Each changed pair carries the best
// similarity score of the matches that propose it, as the match table of the
// Version Tracking window shows.
//@category Hereticus

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingTask;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskLauncher;

public class HereticusVersionTracking extends GhidraScript {

	/** The correlators that pair only functions with the same instructions. */
	private static final Set<String> IDENTICAL = Set.of(
		"Exact Function Bytes Match",
		"Exact Function Instructions Match",
		"Duplicate Function Instructions Match");

	/** What one accepted function pair holds. */
	private static final class Pair {
		final Address source;
		final Address destination;
		double score = 0.0;
		boolean identical = false;

		Pair(Address source, Address destination) {
			this.source = source;
			this.destination = destination;
		}
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2) {
			throw new IllegalArgumentException("usage: SOURCE_PROGRAM OUTPUT_JSON");
		}
		Program destination = currentProgram;
		DomainFile sourceFile = state.getProject().getProjectData().getFile("/" + args[0]);
		if (sourceFile == null) {
			throw new IllegalArgumentException(args[0] + " is not in the project");
		}
		Program source = (Program) sourceFile.getDomainObject(this, true, false, monitor);

		VTSession session = null;
		try {
			// The script transaction holds a lock that Version Tracking needs.
			end(true);
			session = new VTSessionDB("hereticus", source, destination, this);
			AutoVersionTrackingTask task = new AutoVersionTrackingTask(session, options());
			TaskLauncher.launch(task);
			println(task.getStatusMsg());
			write(args[1], source, destination, pairs(session));
		}
		finally {
			source.release(this);
			if (session != null) {
				session.release(this);
			}
		}
	}

	/** The options `AutoVersionTrackingScript` uses when it runs headless. */
	private static ToolOptions options() {
		ToolOptions options = new VTOptions("Hereticus");
		options.setBoolean(VTOptionDefines.CREATE_IMPLIED_MATCHES_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_EXACT_SYMBOL_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_EXACT_DATA_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_BYTES_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_EXACT_FUNCTION_INST_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_DUPE_FUNCTION_OPTION, true);
		options.setBoolean(VTOptionDefines.RUN_REF_CORRELATORS_OPTION, true);
		options.setInt(VTOptionDefines.DATA_CORRELATOR_MIN_LEN_OPTION, 5);
		options.setInt(VTOptionDefines.SYMBOL_CORRELATOR_MIN_LEN_OPTION, 3);
		options.setInt(VTOptionDefines.FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);
		options.setInt(VTOptionDefines.DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION, 10);
		options.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_SCORE_OPTION, 0.95);
		options.setDouble(VTOptionDefines.REF_CORRELATOR_MIN_CONF_OPTION, 10.0);
		options.setBoolean(VTOptionDefines.APPLY_IMPLIED_MATCHES_OPTION, true);
		options.setInt(VTOptionDefines.MIN_VOTES_OPTION, 2);
		options.setInt(VTOptionDefines.MAX_CONFLICTS_OPTION, 0);
		return options;
	}

	/** Each accepted pair of functions with code, with what its matches say. */
	private static Map<VTAssociation, Pair> pairs(VTSession session) {
		Program source = session.getSourceProgram();
		Map<VTAssociation, Pair> pairs = new HashMap<>();
		for (VTMatchSet set : session.getMatchSets()) {
			String correlator = set.getProgramCorrelatorInfo().getName();
			for (VTMatch match : set.getMatches()) {
				VTAssociation association = match.getAssociation();
				if (association.getType() != VTAssociationType.FUNCTION ||
					association.getStatus() != VTAssociationStatus.ACCEPTED ||
					!hasCode(source, association.getSourceAddress())) {
					continue;
				}
				Pair pair = pairs.computeIfAbsent(association,
					a -> new Pair(a.getSourceAddress(), a.getDestinationAddress()));
				pair.score = Math.max(pair.score, match.getSimilarityScore().getScore());
				pair.identical |= IDENTICAL.contains(correlator);
			}
		}
		return pairs;
	}

	/** Whether a function with code of its own starts at `entry`. */
	private static boolean hasCode(Program program, Address entry) {
		Function function = program.getFunctionManager().getFunctionAt(entry);
		return function != null && !function.isThunk() && !function.isExternal();
	}

	/**
	 * The address of `entry` in the file. Ghidra loads a shared object at
	 * 0x10000 and not at the address it is linked at.
	 */
	private static long fileAddress(Program program, Address entry) {
		String linked = program.getOptions(Program.PROGRAM_INFO)
				.getString("ELF Original Image Base", null);
		long base = linked == null ? program.getImageBase().getOffset() : Long.decode(linked);
		return entry.getOffset() - program.getImageBase().getOffset() + base;
	}

	/** The entry of each function of `program` that has code of its own. */
	private static List<Address> functions(Program program) {
		List<Address> entries = new ArrayList<>();
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			if (hasCode(program, function.getEntryPoint())) {
				entries.add(function.getEntryPoint());
			}
		}
		return entries;
	}

	private static void write(String path, Program source, Program destination,
			Map<VTAssociation, Pair> pairs) throws Exception {
		Set<Address> paired = new HashSet<>();
		Set<Address> pairedDestinations = new HashSet<>();
		for (Pair pair : pairs.values()) {
			paired.add(pair.source);
			pairedDestinations.add(pair.destination);
		}
		try (PrintWriter out = new PrintWriter(path, "UTF-8")) {
			out.println("{\"changed\": [");
			String separator = "";
			for (Pair pair : pairs.values()) {
				if (pair.identical) {
					continue;
				}
				out.printf("%s{\"before\": %d, \"after\": %d, \"score\": %.6f}%n", separator,
					fileAddress(source, pair.source), fileAddress(destination, pair.destination),
					pair.score);
				separator = ", ";
			}
			out.println("], \"gone\": [");
			out.println(join(source, paired));
			out.println("], \"new\": [");
			out.println(join(destination, pairedDestinations));
			out.println("]}");
		}
	}

	/** The file address of each function of `program` not in `paired`. */
	private static String join(Program program, Set<Address> paired) {
		StringBuilder joined = new StringBuilder();
		for (Address entry : functions(program)) {
			if (paired.contains(entry)) {
				continue;
			}
			if (joined.length() > 0) {
				joined.append(", ");
			}
			joined.append(fileAddress(program, entry));
		}
		return joined.toString();
	}
}
