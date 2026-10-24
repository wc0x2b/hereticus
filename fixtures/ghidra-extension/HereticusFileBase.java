// Write the address of the first byte of the imported file, as one
// hexadecimal address, to the file the first argument names. Run by
// `fixtures/ghidra_extension.sh`, to show the base that the Hereticus raw
// loader gave.
//
// Raw Binary keeps the image base at 0 and puts the file at its Base
// Address, so the image base does not show the base.
//@category Hereticus

import java.io.PrintWriter;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class HereticusFileBase extends GhidraScript {

	@Override
	public void run() throws Exception {
		List<Address> starts = currentProgram.getMemory().locateAddressesForFileOffset(0);
		if (starts.isEmpty()) {
			throw new IllegalStateException("no address holds the first byte of the file");
		}
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
			out.println(Long.toHexString(starts.get(0).getOffset()));
		}
	}
}
