package hereticus;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The hereticus command line tool, run as a child process.
 *
 * The extension holds no analysis of its own. It gives each program to the
 * tool and reads the JSON the tool prints, so the extension finds and pairs
 * the functions exactly as the command line does.
 */
public final class HereticusTool {

	/** The name a user gives when hereticus is on the PATH. */
	public static final String DEFAULT_EXECUTABLE = "hereticus";

	/** How often a run looks whether the user cancelled it. */
	private static final long POLL_MILLISECONDS = 100;

	private final String executable;

	public HereticusTool(String executable) {
		this.executable = executable;
	}

	/**
	 * Runs the tool and returns what it wrote to standard output.
	 *
	 * @param arguments the arguments, without the executable
	 * @param monitor a cancel of this kills the tool
	 * @return standard output, as UTF-8 text
	 * @throws HereticusException if the tool does not start or exits with a failure
	 * @throws CancelledException if the user cancelled the run
	 */
	public String run(List<String> arguments, TaskMonitor monitor)
			throws HereticusException, CancelledException {
		List<String> command = new ArrayList<>();
		command.add(executable);
		// A progress bar on standard error would only fill the log.
		command.add("--progress");
		command.add("never");
		command.addAll(arguments);

		Path errors = createTempFile();
		try {
			Process process = start(command, errors);
			// Standard output is read while the tool runs: a listing of a large
			// kernel fills the pipe, and the tool then waits for a reader.
			CompletableFuture<byte[]> output =
				CompletableFuture.supplyAsync(() -> readAll(process.getInputStream()));
			waitFor(process, monitor);
			String stdout = new String(join(output), StandardCharsets.UTF_8);
			if (process.exitValue() != 0) {
				throw new HereticusException(
					"hereticus failed with exit status " + process.exitValue() + ": " +
						read(errors).strip());
			}
			return stdout;
		}
		finally {
			delete(errors);
		}
	}

	private Process start(List<String> command, Path errors) throws HereticusException {
		try {
			return new ProcessBuilder(command)
					.redirectInput(Redirect.from(nullDevice()))
					.redirectError(errors.toFile())
					.start();
		}
		catch (IOException e) {
			throw new HereticusException("cannot run `" + executable + "`: " + e.getMessage() +
				". Install hereticus on the PATH, or give its path in the options.", e);
		}
	}

	private static java.io.File nullDevice() {
		boolean windows = System.getProperty("os.name", "").startsWith("Windows");
		return new java.io.File(windows ? "NUL" : "/dev/null");
	}

	private static void waitFor(Process process, TaskMonitor monitor)
			throws CancelledException, HereticusException {
		try {
			while (!process.waitFor(POLL_MILLISECONDS, TimeUnit.MILLISECONDS)) {
				if (monitor.isCancelled()) {
					process.destroyForcibly();
					throw new CancelledException();
				}
			}
		}
		catch (InterruptedException e) {
			process.destroyForcibly();
			Thread.currentThread().interrupt();
			throw new HereticusException("interrupted while hereticus ran", e);
		}
	}

	private static byte[] readAll(InputStream stream) {
		try (stream) {
			return stream.readAllBytes();
		}
		catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static byte[] join(CompletableFuture<byte[]> output) throws HereticusException {
		try {
			return output.get();
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new HereticusException("interrupted while reading hereticus", e);
		}
		catch (ExecutionException e) {
			throw new HereticusException("cannot read the output of hereticus: " +
				e.getCause().getMessage(), e.getCause());
		}
	}

	private static Path createTempFile() throws HereticusException {
		try {
			return Files.createTempFile("hereticus", ".stderr");
		}
		catch (IOException e) {
			throw new HereticusException("cannot make a temporary file: " + e.getMessage(), e);
		}
	}

	private static String read(Path path) throws HereticusException {
		try {
			return Files.readString(path, StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			throw new HereticusException("cannot read the errors of hereticus: " +
				e.getMessage(), e);
		}
	}

	private static void delete(Path path) {
		try {
			Files.deleteIfExists(path);
		}
		catch (IOException e) {
			// A temporary file left behind does no harm, and the result is good.
		}
	}
}
