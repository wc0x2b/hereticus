package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.OptionalLong;
import java.util.Random;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.util.task.TaskMonitor;

class BaseSearchTest {

	/** What `hereticus --find-base --format json` printed for Cortex-M3 firmware. */
	private static final String FOUND = """
		{"base":134217728,"candidates":[\
		{"base":134217728,"strings":40,"functions":12,"by_chance":1.0,"evidence":51.0,\
		"halves":false}]}""";

	@TempDir
	Path directory;

	@Test
	void readsTheBase() throws HereticusException {
		assertEquals(OptionalLong.of(0x0800_0000L), BaseSearch.parse(FOUND).offset());
	}

	@Test
	void aNullBaseIsNoBase() throws HereticusException {
		assertEquals(OptionalLong.empty(),
			BaseSearch.parse("{\"base\":null,\"candidates\":[]}").offset());
	}

	/** Any 64-bit base reads back as the same 64 bits. */
	@Test
	void everyBaseReadsBackAsItsBits() throws HereticusException {
		Random random = new Random(0x4865726574696375L);
		for (int round = 0; round < 1000; round++) {
			long bits = random.nextLong();
			String unsigned = Long.toUnsignedString(bits);
			assertEquals(OptionalLong.of(bits),
				BaseSearch.parse("{\"base\":" + unsigned + "}").offset(), unsigned);
		}
	}

	@Test
	void textThatIsNotTheJsonFails() {
		assertThrows(HereticusException.class, () -> BaseSearch.parse("No base stands out"));
		assertThrows(HereticusException.class, () -> BaseSearch.parse(""));
		assertThrows(HereticusException.class, () -> BaseSearch.parse("{\"base\":\"high\"}"));
	}

	@Test
	void theArgumentsNameTheInstructionSetAndTheImage() {
		assertEquals(
			List.of("--raw", "--find-base", "--arch", "thumb2", "--format", "json", "a.bin"),
			BaseSearch.arguments(InstructionSet.THUMB2, Path.of("a.bin")));
	}

	/** The tool gets the arguments, and its output is read as the base. */
	@Test
	void findsTheBaseThatTheToolPrints() throws Exception {
		HereticusTool tool = script("""
			[ "$*" = "--progress never --raw --find-base --arch mips32-be --format json a.bin" ] \
			|| exit 3
			echo '{"base":2147483648,"candidates":[]}'""");
		assertEquals(OptionalLong.of(0x8000_0000L),
			BaseSearch.find(tool, InstructionSet.MIPS32_BE, Path.of("a.bin"), TaskMonitor.DUMMY));
	}

	@Test
	void aFailureOfTheToolIsAnError() throws IOException {
		HereticusTool tool = script("echo 'hereticus: cannot read a.bin' >&2; exit 2");
		assertThrows(HereticusException.class,
			() -> BaseSearch.find(tool, InstructionSet.ARM32, Path.of("a.bin"),
				TaskMonitor.DUMMY));
	}

	private HereticusTool script(String body) throws IOException {
		Path path = directory.resolve("hereticus");
		Files.writeString(path, "#!/bin/sh\n" + body + "\n");
		Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
		return new HereticusTool(path.toString());
	}
}
