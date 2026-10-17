// Write the linked address of each function Ghidra holds in the program, one
// hexadecimal address a line, to the file the first argument names. Run by
// `fixtures/ghidra_extension.sh`.
//
// Ghidra loads a shared object linked at 0 at 0x10000. The address the file
// links each function at is the one hereticus reports, so the test can
// compare the two.
//@category Hereticus

import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.listing.Function;

public class HereticusExtensionStarts extends GhidraScript {

	@Override
	public void run() throws Exception {
		Long linked = ElfLoader.getElfOriginalImageBase(currentProgram);
		long shift = linked == null ? 0 : currentProgram.getImageBase().getOffset() - linked;
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
			for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
				// A thunk has code of its own, as a PLT entry or a branch to
				// another function, and hereticus lists it as a function.
				if (function.isExternal()) {
					continue;
				}
				out.println(Long.toHexString(function.getEntryPoint().getOffset() - shift));
			}
		}
	}
}
