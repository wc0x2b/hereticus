package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Runs shell scripts in place of hereticus, to test how a run ends. */
class HereticusToolTest {

	@TempDir
	Path directory;

	private HereticusTool script(String body) throws IOException {
		Path path = directory.resolve("hereticus");
		Files.writeString(path, "#!/bin/sh\n" + body + "\n");
		Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
		return new HereticusTool(path.toString());
	}

	@Test
	void returnsWhatTheToolPrints() throws Exception {
		HereticusTool tool = script("echo \"$@\"");
		assertEquals("--progress never --functions a.bin\n",
			tool.run(List.of("--functions", "a.bin"), TaskMonitor.DUMMY));
	}

	/** Standard output is read while the tool runs, so a big listing cannot block it. */
	@Test
	void readsAnOutputLargerThanAPipe() throws Exception {
		HereticusTool tool = script("head -c 8000000 /dev/zero; echo error >&2");
		String output = assertTimeoutPreemptively(Duration.ofSeconds(30),
			() -> tool.run(List.of(), TaskMonitor.DUMMY));
		assertEquals(8_000_000, output.length());
	}

	@Test
	void aFailureCarriesTheStatusAndTheErrorOfTheTool() throws Exception {
		HereticusTool tool = script("echo 'hereticus: cannot read a.bin' >&2; exit 2");
		HereticusException failure = assertThrows(HereticusException.class,
			() -> tool.run(List.of(), TaskMonitor.DUMMY));
		assertTrue(failure.getMessage().contains("exit status 2"), failure.getMessage());
		assertTrue(failure.getMessage().contains("cannot read a.bin"), failure.getMessage());
	}

	@Test
	void aMissingToolSaysWhereToPutIt() {
		HereticusTool tool = new HereticusTool(directory.resolve("absent").toString());
		HereticusException failure = assertThrows(HereticusException.class,
			() -> tool.run(List.of(), TaskMonitor.DUMMY));
		assertTrue(failure.getMessage().contains("in the options"), failure.getMessage());
	}

	@Test
	void aCancelStopsTheTool() throws Exception {
		HereticusTool tool = script("sleep 60");
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		assertTimeoutPreemptively(Duration.ofSeconds(10),
			() -> assertThrows(CancelledException.class, () -> tool.run(List.of(), monitor)));
	}
}
