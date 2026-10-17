package hereticus;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTMatchTag;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Proposes each pair of functions hereticus finds between the source and the
 * destination program.
 *
 * A pair is proposed where both programs have a function at its addresses.
 * Run the Hereticus Function Finder on both first, so a function only
 * hereticus found has a Ghidra function to pair.
 */
public class HereticusProgramCorrelator extends VTAbstractProgramCorrelator {

	/** The start of the name of each tag this correlator gives a match. */
	static final String TAG_PREFIX = "hereticus: ";

	public HereticusProgramCorrelator(Program sourceProgram, AddressSetView sourceAddressSet,
			Program destinationProgram, AddressSetView destinationAddressSet,
			ToolOptions options) {
		super(sourceProgram, sourceAddressSet, destinationProgram, destinationAddressSet,
			options);
	}

	@Override
	public String getName() {
		return HereticusProgramCorrelatorFactory.NAME;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Running hereticus");
		DiffReport report;
		LinkedAddresses source;
		LinkedAddresses destination;
		try (ProgramFile sourceFile = ProgramFile.write(getSourceProgram());
				ProgramFile destinationFile = ProgramFile.write(getDestinationProgram())) {
			String executable = getOptions().getString(
				HereticusProgramCorrelatorFactory.OPTION_EXECUTABLE,
				HereticusTool.DEFAULT_EXECUTABLE);
			report = DiffReport.parse(new HereticusTool(executable)
					.run(arguments(sourceFile, destinationFile), monitor));
			source = LinkedAddresses.of(getSourceProgram(), sourceFile);
			destination = LinkedAddresses.of(getDestinationProgram(), destinationFile);
		}
		catch (HereticusException e) {
			// Version Tracking shows the message of what a correlator throws.
			throw new IllegalStateException(e.getMessage(), e);
		}

		Map<String, VTMatchTag> tags = new HashMap<>();
		int skipped = 0;
		monitor.initialize(report.pairs().size(), "Adding the pairs hereticus found");
		for (DiffReport.Pair pair : report.pairs()) {
			monitor.increment();
			Function before = functionAt(getSourceProgram(), getSourceAddressSet(),
				source.toProgram(pair.before().offset()));
			Function after = functionAt(getDestinationProgram(), getDestinationAddressSet(),
				destination.toProgram(pair.after().offset()));
			if (before == null || after == null) {
				skipped++;
				continue;
			}
			VTMatchTag tag = tags.computeIfAbsent(pair.change(),
				change -> tag(matchSet.getSession(), change));
			matchSet.addMatch(match(matchSet, pair, before, after, tag));
		}
		if (skipped > 0) {
			Msg.info(this, skipped + " pairs of hereticus have no Ghidra function on one side. " +
				"Run the " + HereticusFunctionAnalyzer.NAME + " on both programs to pair them.");
		}
	}

	/** The arguments that compare the two files and report every pair. */
	private List<String> arguments(ProgramFile source, ProgramFile destination)
			throws HereticusException {
		if (!source.readArguments().equals(destination.readArguments())) {
			throw new HereticusException("hereticus reads both programs alike, but one is " +
				"raw and the other not, or they load at other bases or in other " +
				"instruction sets: " + source.readArguments() + " and " +
				destination.readArguments());
		}
		List<String> arguments = new ArrayList<>(source.readArguments());
		arguments.addAll(List.of("--format", "json", "--all", "--threshold",
			Double.toString(getOptions().getDouble(
				HereticusProgramCorrelatorFactory.OPTION_THRESHOLD,
				HereticusProgramCorrelatorFactory.DEFAULT_THRESHOLD))));
		if (getOptions().getBoolean(HereticusProgramCorrelatorFactory.OPTION_IGNORE_NAMES,
			false)) {
			arguments.add("--ignore-names");
		}
		arguments.add(source.path().toString());
		arguments.add(destination.path().toString());
		return arguments;
	}

	/** The function that starts at `entry`, where it is one this correlation may pair. */
	private static Function functionAt(Program program, AddressSetView set, Address entry) {
		if (entry == null || !set.contains(entry)) {
			return null;
		}
		return program.getFunctionManager().getFunctionAt(entry);
	}

	/** The tag of the session for `change`, made the first time it is needed. */
	private static VTMatchTag tag(VTSession session, String change) {
		String name = TAG_PREFIX + change;
		return session.getMatchTags()
				.stream()
				.filter(tag -> tag.getName().equals(name))
				.findFirst()
				.orElseGet(() -> session.createMatchTag(name));
	}

	private static VTMatchInfo match(VTMatchSet matchSet, DiffReport.Pair pair, Function before,
			Function after, VTMatchTag tag) {
		VTMatchInfo match = new VTMatchInfo(matchSet);
		match.setAssociationType(VTAssociationType.FUNCTION);
		match.setSourceAddress(before.getEntryPoint());
		match.setSourceLength((int) before.getBody().getNumAddresses());
		match.setDestinationAddress(after.getEntryPoint());
		match.setDestinationLength((int) after.getBody().getNumAddresses());
		match.setSimilarityScore(new VTScore(pair.score()));
		match.setConfidenceScore(new VTScore(Confidence.of(pair.matchedBy())));
		match.setTag(tag);
		return match;
	}
}
