package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LinkedAddressesTest {

	@Test
	void aSharedObjectLinkedAtZeroMovesToWhereGhidraLoadedIt() {
		assertEquals(0x10000, LinkedAddresses.shift(0x10000, 0L));
	}

	@Test
	void anExecutableLoadedWhereItIsLinkedDoesNotMove() {
		assertEquals(0, LinkedAddresses.shift(0x400000, 0x400000L));
	}

	@Test
	void aProgramMovedDownMovesBack() {
		assertEquals(-0x1000, LinkedAddresses.shift(0x7000, 0x8000L));
	}

	@Test
	void withoutALinkedBaseNothingMoves() {
		assertEquals(0, LinkedAddresses.shift(0x10000, null));
	}
}
