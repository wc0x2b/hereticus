package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Random;

import org.junit.jupiter.api.Test;

class FunctionListingTest {

	/** What `hereticus --functions --format json` printed for a raw ARM stub. */
	private static final String LISTING = """
		{"isa":"arm32","found_by":"scanning","functions":[\
		{"name":"sub_80208000","address":2149613568,"size":64,"isa":"arm32","holds":"code"},\
		{"name":"sub_80208040","address":2149613632,"size":8,"isa":"thumb2","holds":"code"},\
		{"name":"sub_80209000","address":2149617664,"size":512,"isa":"arm32","holds":"data"}]}""";

	@Test
	void readsEachFunction() throws HereticusException {
		FunctionListing listing = FunctionListing.parse(LISTING);
		assertEquals(InstructionSet.ARM32, listing.isa());
		assertEquals("scanning", listing.foundBy());
		assertEquals(3, listing.functions().size());

		FunctionListing.Listed first = listing.functions().get(0);
		assertEquals("sub_80208000", first.name());
		assertEquals(0x8020_8000L, first.offset());
		assertEquals(64, first.size());
		assertEquals(InstructionSet.THUMB2, listing.functions().get(1).isa());
		assertEquals(FunctionListing.Contents.DATA, listing.functions().get(2).holds());
	}

	/** An AArch64 kernel links above 2^63, past what a signed long holds. */
	@Test
	void anAddressAboveTheSignedRangeKeepsItsBits() throws HereticusException {
		FunctionListing listing = FunctionListing.parse("""
			{"isa":"aarch64","found_by":"scanning","functions":[\
			{"name":"x","address":18446603336489631744,"size":4,"isa":"aarch64","holds":"code"}]}""");
		assertEquals(0xffff_8000_1000_0000L, listing.functions().get(0).offset());
	}

	/** Any 64-bit address reads back as the same 64 bits. */
	@Test
	void everyAddressReadsBackAsItsBits() throws HereticusException {
		Random random = new Random(0x4865726574696375L);
		for (int round = 0; round < 1000; round++) {
			long bits = random.nextLong();
			String unsigned = Long.toUnsignedString(bits);
			FunctionListing listing = FunctionListing.parse("{\"functions\":[{\"address\":" +
				unsigned + ",\"size\":4,\"isa\":\"mips32\",\"holds\":\"code\"}]}");
			assertEquals(bits, listing.functions().get(0).offset(), unsigned);
			assertEquals(new BigInteger(unsigned), listing.functions().get(0).address());
		}
	}

	@Test
	void anEmptyListingIsAListing() throws HereticusException {
		assertTrue(FunctionListing.parse("{\"functions\":[]}").functions().isEmpty());
	}

	@Test
	void rejectsWhatIsNotAListing() {
		assertThrows(HereticusException.class, () -> FunctionListing.parse(""));
		assertThrows(HereticusException.class, () -> FunctionListing.parse("not json"));
		assertThrows(HereticusException.class, () -> FunctionListing.parse("{}"));
		assertThrows(HereticusException.class, () -> FunctionListing.parse("{\"functions\":[{}]}"));
		assertThrows(HereticusException.class, () -> FunctionListing.parse(
			"{\"functions\":[{\"address\":0,\"isa\":\"arm32\",\"holds\":\"maybe\"}]}"));
		assertThrows(HereticusException.class, () -> FunctionListing.parse(
			"{\"functions\":[{\"address\":0,\"isa\":\"z80\",\"holds\":\"code\"}]}"));
		assertThrows(HereticusException.class, () -> FunctionListing.parse(
			"{\"functions\":[{\"address\":\"0x10\",\"isa\":\"arm32\",\"holds\":\"code\"}]}"));
	}
}
