// Run the Hereticus Function Match correlator of Version Tracking, and write
// the matches it proposes as JSON. Run by `fixtures/ghidra_extension.sh`.
//
// The current program is the destination, the later side. The first argument
// names the source program in the same project, the second the hereticus
// executable, and the third the JSON file to write:
//
//   {"matches": [{"before": 1234, "after": 1250, "score": 0.82,
//                 "confidence": 2.0, "tag": "hereticus: changed"}, ...]}
//
// Each address is where the file links the function.
//@category Hereticus

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class HereticusCorrelate extends GhidraScript {

	private static final String CORRELATOR = "Hereticus Function Match";

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 3) {
			throw new IllegalArgumentException("usage: SOURCE_PROGRAM HERETICUS OUTPUT_JSON");
		}
		Program destination = currentProgram;
		DomainFile sourceFile = state.getProject().getProjectData().getFile("/" + args[0]);
		if (sourceFile == null) {
			throw new IllegalArgumentException(args[0] + " is not in the project");
		}
		Program source = (Program) sourceFile.getDomainObject(this, true, false, monitor);
		VTSessionDB session = null;
		try {
			// The script transaction holds a lock that Version Tracking needs.
			end(true);
			session = new VTSessionDB("hereticus", source, destination, this);
			VTProgramCorrelatorFactory factory = factory();
			VTOptions options = factory.createDefaultOptions();
			options.setString("Hereticus Executable", args[1]);
			VTProgramCorrelator correlator = factory.createCorrelator(source,
				source.getMemory().getLoadedAndInitializedAddressSet(), destination,
				destination.getMemory().getLoadedAndInitializedAddressSet(), options);
			int transaction = session.startTransaction("Correlate");
			VTMatchSet matches;
			try {
				matches = correlator.correlate(session, monitor);
			}
			finally {
				session.endTransaction(transaction, true);
			}
			write(args[2], source, destination, matches);
			println(CORRELATOR + " proposed " + matches.getMatchCount() + " matches");
		}
		finally {
			source.release(this);
			if (session != null) {
				session.release(this);
			}
		}
	}

	/** The factory of the correlator, as Version Tracking finds it among the extensions. */
	private static VTProgramCorrelatorFactory factory() {
		for (VTProgramCorrelatorFactory factory : ClassSearcher
				.getInstances(VTProgramCorrelatorFactory.class)) {
			if (factory.getName().equals(CORRELATOR)) {
				return factory;
			}
		}
		throw new IllegalStateException(CORRELATOR + " is not installed");
	}

	private static long linked(Program program, Address address) {
		Long base = ElfLoader.getElfOriginalImageBase(program);
		long shift = base == null ? 0 : program.getImageBase().getOffset() - base;
		return address.getOffset() - shift;
	}

	private static void write(String path, Program source, Program destination,
			VTMatchSet matches) throws Exception {
		try (PrintWriter out = new PrintWriter(path, "UTF-8")) {
			out.println("{\"matches\": [");
			String separator = "";
			for (VTMatch match : matches.getMatches()) {
				out.printf("%s{\"before\": %d, \"after\": %d, \"score\": %.6f, " +
					"\"confidence\": %.3f, \"tag\": \"%s\"}%n", separator,
					linked(source, match.getSourceAddress()),
					linked(destination, match.getDestinationAddress()),
					match.getSimilarityScore().getScore(),
					match.getConfidenceScore().getScore(), match.getTag().getName());
				separator = ", ";
			}
			out.println("]}");
		}
	}
}
