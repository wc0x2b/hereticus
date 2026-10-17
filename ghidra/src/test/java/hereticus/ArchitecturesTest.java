package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.junit.jupiter.api.Test;

class ArchitecturesTest {

	@Test
	void aCortexPartIsThumbAndAnotherArmIsA32() {
		assertEquals(Optional.of(InstructionSet.THUMB2),
			Architectures.of("ARM", false, 32, "Cortex"));
		assertEquals(Optional.of(InstructionSet.ARM32), Architectures.of("ARM", false, 32, "v8"));
		assertEquals(Optional.of(InstructionSet.ARM32), Architectures.of("ARM", false, 32, "v5t"));
	}

	@Test
	void eachMipsByteOrderHasItsOwnSet() {
		assertEquals(Optional.of(InstructionSet.MIPS32),
			Architectures.of("MIPS", false, 32, "default"));
		assertEquals(Optional.of(InstructionSet.MIPS32_BE),
			Architectures.of("MIPS", true, 32, "default"));
	}

	@Test
	void aarch64IsLittleEndianOnly() {
		assertEquals(Optional.of(InstructionSet.AARCH64),
			Architectures.of("AARCH64", false, 64, "v8A"));
		assertEquals(Optional.empty(), Architectures.of("AARCH64", true, 64, "v8A"));
	}

	@Test
	void whatHereticusCannotReadHasNoSet() {
		assertEquals(Optional.empty(), Architectures.of("ARM", true, 32, "v8"));
		assertEquals(Optional.empty(), Architectures.of("MIPS", false, 64, "default"));
		assertEquals(Optional.empty(), Architectures.of("MIPS", false, 32, "R6"));
		assertEquals(Optional.empty(), Architectures.of("MIPS", true, 32, "micro"));
		assertEquals(Optional.empty(), Architectures.of("x86", false, 64, "default"));
		assertEquals(Optional.empty(), Architectures.of("", false, 0, ""));
	}
}
