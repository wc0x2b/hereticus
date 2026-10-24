package hereticus;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.ElfLoader;

class ProgramFileTest {

	@Test
	void bothRawLoadersLoadRawCode() {
		assertTrue(ProgramFile.isRaw(BinaryLoader.BINARY_NAME));
		assertTrue(ProgramFile.isRaw(HereticusRawLoader.NAME));
	}

	@Test
	void aContainerIsNotRaw() {
		assertFalse(ProgramFile.isRaw(ElfLoader.ELF_NAME));
		assertFalse(ProgramFile.isRaw(null));
	}
}
