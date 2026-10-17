package hereticus;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.util.opinion.BinaryLoader;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The file a program was imported from, written out again for hereticus to
 * read.
 *
 * Ghidra keeps the bytes of the imported file, as they were before any edit.
 * Those are the bytes the addresses of the program come from, and the path it
 * was imported from may be gone.
 */
public final class ProgramFile implements AutoCloseable {

	/** How hereticus must read the file. */
	public enum Kind {
		/** A format that says where it loads, as ELF or Mach-O. */
		CONTAINER,
		/** Raw code, which needs a base and an instruction set. */
		RAW
	}

	/** How much of the file one read copies. */
	private static final int CHUNK = 1 << 20;

	private final Path path;
	private final Kind kind;
	private final List<String> readArguments;

	private ProgramFile(Path path, Kind kind, List<String> readArguments) {
		this.path = path;
		this.kind = kind;
		this.readArguments = readArguments;
	}

	/**
	 * Writes the imported file of `program` to a temporary file, which
	 * {@link #close()} deletes.
	 *
	 * @throws HereticusException if the program keeps no file, or hereticus
	 *         cannot read it
	 */
	public static ProgramFile write(Program program) throws HereticusException {
		Kind kind = BinaryLoader.BINARY_NAME.equals(program.getExecutableFormat()) ? Kind.RAW
				: Kind.CONTAINER;
		List<String> readArguments = kind == Kind.RAW ? rawArguments(program) : List.of();
		FileBytes bytes = importedFile(program);
		Path path;
		try {
			path = Files.createTempFile("hereticus", ".bin");
		}
		catch (IOException e) {
			throw new HereticusException("cannot make a temporary file: " + e.getMessage(), e);
		}
		try {
			copy(bytes, path);
		}
		catch (IOException e) {
			deleteQuietly(path);
			throw new HereticusException("cannot write " + program.getName() + " for hereticus: " +
				e.getMessage(), e);
		}
		return new ProgramFile(path, kind, readArguments);
	}

	/** Where the file is. */
	public Path path() {
		return path;
	}

	public Kind kind() {
		return kind;
	}

	/**
	 * What hereticus needs to read the file: for a raw image, `--raw`, the
	 * base and the instruction set, and for a container nothing.
	 */
	public List<String> readArguments() {
		return readArguments;
	}

	@Override
	public void close() {
		deleteQuietly(path);
	}

	/**
	 * The arguments that read a raw image as Ghidra loaded it: at the address
	 * of its first byte, in the instruction set of its language.
	 */
	private static List<String> rawArguments(Program program) throws HereticusException {
		InstructionSet isa = Architectures.of(program.getLanguage())
				.orElseThrow(() -> new HereticusException("hereticus cannot read " +
					program.getLanguage().getLanguageID() + " code"));
		List<Address> starts = program.getMemory().locateAddressesForFileOffset(0);
		if (starts.isEmpty()) {
			throw new HereticusException("no address of " + program.getName() +
				" holds the first byte of its file, so its base is not known");
		}
		String base = "0x" + Long.toHexString(starts.get(0).getOffset());
		return List.of("--raw", "--base", base, "--arch", isa.archName());
	}

	/**
	 * The bytes of the file `program` was imported from. A program can hold
	 * more than one file; the one named as the program is the one imported.
	 */
	private static FileBytes importedFile(Program program) throws HereticusException {
		List<FileBytes> files = program.getMemory().getAllFileBytes();
		if (files.isEmpty()) {
			throw new HereticusException(program.getName() +
				" keeps no bytes of the file it was imported from");
		}
		return files.stream()
				.filter(file -> file.getFilename().equals(program.getName()))
				.findFirst()
				.orElse(files.get(0));
	}

	private static void copy(FileBytes bytes, Path path) throws IOException {
		byte[] buffer = new byte[CHUNK];
		try (OutputStream out = Files.newOutputStream(path)) {
			for (long offset = 0; offset < bytes.getSize(); offset += CHUNK) {
				int length = (int) Math.min(CHUNK, bytes.getSize() - offset);
				int read = bytes.getOriginalBytes(offset, buffer, 0, length);
				if (read != length) {
					throw new IOException("read " + read + " bytes at offset " + offset +
						", not " + length);
				}
				out.write(buffer, 0, length);
			}
		}
	}

	private static void deleteQuietly(Path path) {
		try {
			Files.deleteIfExists(path);
		}
		catch (IOException e) {
			// A temporary file left behind does no harm.
		}
	}
}
