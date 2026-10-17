package hereticus;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Makes a function at each start hereticus finds that Ghidra missed.
 *
 * hereticus reads the exception index, the symbols, and the calls and
 * prologues of the code. On a stripped binary or a raw image it finds starts
 * that the analysis of Ghidra does not reach.
 */
public class HereticusFunctionAnalyzer extends AbstractAnalyzer {

	static final String NAME = "Hereticus Function Finder";
	private static final String DESCRIPTION =
		"Runs the hereticus command line tool on the imported file, and makes a function at " +
			"each start it finds that Ghidra did not. A start inside a function or on data " +
			"that Ghidra defined is left alone.";

	static final String OPTION_EXECUTABLE = "Hereticus Executable";
	private static final String OPTION_EXECUTABLE_DESCRIPTION =
		"The path of the hereticus tool, or its name if it is on the PATH.";

	private String executable = HereticusTool.DEFAULT_EXECUTABLE;

	public HereticusFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// After the functions that flow and symbols show: a scan is more of a
		// guess, and should fill the gaps those leave rather than come first.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Architectures.of(program.getLanguage()).isPresent();
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_EXECUTABLE, HereticusTool.DEFAULT_EXECUTABLE, null,
			OPTION_EXECUTABLE_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		executable = options.getString(OPTION_EXECUTABLE, HereticusTool.DEFAULT_EXECUTABLE);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Running hereticus");
		FunctionListing listing;
		LinkedAddresses addresses;
		try (ProgramFile file = ProgramFile.write(program)) {
			List<String> arguments = new ArrayList<>(file.readArguments());
			arguments.addAll(List.of("--functions", "--format", "json", file.path().toString()));
			listing = FunctionListing.parse(new HereticusTool(executable).run(arguments, monitor));
			addresses = LinkedAddresses.of(program, file);
		}
		catch (HereticusException e) {
			log.appendMsg(NAME, e.getMessage());
			log.setStatus(e.getMessage());
			return false;
		}
		Map<FunctionMaker.Outcome, Integer> counts =
			new FunctionMaker(program, addresses).make(listing, set, monitor);
		String summary = "Of " + listing.functions().size() + " starts hereticus found in " +
			program.getName() + ": " + FunctionMaker.summary(counts);
		log.appendMsg(NAME, summary);
		// The log of the analysis shows only failures, so the summary goes to
		// the application log too, where a headless run shows it.
		Msg.info(this, summary);
		return true;
	}
}
