// Before analysis: point the Hereticus Function Finder at the hereticus
// executable the first argument names, and turn it on or off as the second,
// `on` or `off`, says. Run by `fixtures/ghidra_extension.sh`.
//@category Hereticus

import ghidra.app.script.GhidraScript;

public class HereticusSetup extends GhidraScript {

	private static final String ANALYZER = "Hereticus Function Finder";

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2 || !(args[1].equals("on") || args[1].equals("off"))) {
			throw new IllegalArgumentException("usage: HERETICUS on|off");
		}
		// An analyzer the extension does not register has no option to set,
		// and setting one would pass silently.
		if (!getCurrentAnalysisOptionsAndValues(currentProgram).containsKey(ANALYZER)) {
			throw new IllegalStateException(ANALYZER + " is not installed");
		}
		setAnalysisOption(currentProgram, ANALYZER, Boolean.toString(args[1].equals("on")));
		setAnalysisOption(currentProgram, ANALYZER + ".Hereticus Executable", args[0]);
	}
}
