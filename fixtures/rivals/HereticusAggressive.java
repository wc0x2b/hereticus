// Turn on the Aggressive Instruction Finder, which Ghidra leaves off by
// default. Run by `fixtures/rivals_kernel.sh` before the analysis.
//@category Hereticus

import ghidra.app.script.GhidraScript;

public class HereticusAggressive extends GhidraScript {

	@Override
	public void run() throws Exception {
		setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "true");
	}
}
