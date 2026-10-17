// Write the entry of each function Ghidra found, one hexadecimal address
// a line, to the file the first argument names. Run by
// `fixtures/rivals_kernel.sh`.
//@category Hereticus

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class HereticusFunctionStarts extends GhidraScript {

	@Override
	public void run() throws Exception {
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				out.println(Long.toHexString(function.getEntryPoint().getOffset()));
			}
		}
	}
}
