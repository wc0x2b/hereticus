package hereticus;

import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/** Offers the pairs hereticus finds as a correlator of Version Tracking. */
public class HereticusProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {

	static final String NAME = "Hereticus Function Match";
	private static final String DESCRIPTION =
		"Runs the hereticus command line tool on the two imported files, and proposes each " +
			"pair of functions it finds. Each match is tagged with what changed, as " +
			"`hereticus: changed`, and scored as hereticus scores it. hereticus pairs " +
			"functions that a compiler rewrote, where the exact correlators find nothing.";

	static final String OPTION_EXECUTABLE = "Hereticus Executable";
	static final String OPTION_THRESHOLD = "Lowest Similarity";
	static final double DEFAULT_THRESHOLD = 0.65;
	static final String OPTION_IGNORE_NAMES = "Ignore Symbol Names";

	/** Where the correlator sits in the list: after the exact ones, near the end. */
	private static final int PRIORITY = 90;

	@Override
	public int getPriority() {
		return PRIORITY;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(NAME);
		options.setString(OPTION_EXECUTABLE, HereticusTool.DEFAULT_EXECUTABLE);
		options.setDouble(OPTION_THRESHOLD, DEFAULT_THRESHOLD);
		options.setBoolean(OPTION_IGNORE_NAMES, false);
		return options;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new HereticusProgramCorrelator(sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
	}
}
