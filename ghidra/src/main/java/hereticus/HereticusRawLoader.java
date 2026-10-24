package hereticus;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The Raw Binary loader of Ghidra, with the base that `hereticus --find-base`
 * finds as the default Base Address.
 *
 * The base is found for the language of the import, as the user selects it.
 * Where hereticus cannot read the language, or no base stands out, the Base
 * Address is the one Raw Binary gives.
 */
public class HereticusRawLoader extends BinaryLoader {

	/** The name of the loader, and the executable format of what it loads. */
	public static final String NAME = "Raw Binary (Hereticus Base)";

	/** After Raw Binary, so that a file with no format still opens as Raw Binary. */
	private static final int TIER_PRIORITY = 101;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public int getTierPriority() {
		return TIER_PRIORITY;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> options =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
				mirrorFsLayout);
		findBase(provider, loadSpec).ifPresent(base -> options.stream()
				.filter(option -> option.getName().equals(OPTION_NAME_BASE_ADDR))
				.forEach(option -> option.setValue(base)));
		return options;
	}

	/** The base hereticus finds, or nothing where it finds none. */
	private Optional<Address> findBase(ByteProvider provider, LoadSpec loadSpec) {
		LanguageID languageId = loadSpec.getLanguageCompilerSpec().languageID;
		try {
			Optional<InstructionSet> isa =
				Architectures.of(getLanguageService().getLanguageDescription(languageId));
			if (isa.isEmpty()) {
				return Optional.empty();
			}
			OptionalLong offset = findOffset(provider, isa.get());
			if (offset.isEmpty()) {
				Msg.info(this, "hereticus finds no base that stands out in " +
					provider.getName() + ", so give the Base Address");
				return Optional.empty();
			}
			Address base = getLanguageService().getLanguage(languageId)
					.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(offset.getAsLong());
			Msg.info(this, "hereticus finds that " + provider.getName() + " loads at " + base);
			return Optional.of(base);
		}
		// The import goes on at the Base Address of Raw Binary, so a failure
		// is a warning, not an error. An IOException includes an unknown
		// language.
		catch (HereticusException | IOException | AddressOutOfBoundsException e) {
			Msg.warn(this, "hereticus cannot find the base of " + provider.getName() + ": " +
				e.getMessage());
		}
		catch (CancelledException e) {
			// Nothing cancels TaskMonitor.DUMMY.
		}
		return Optional.empty();
	}

	/**
	 * Runs hereticus on the file of `provider`. A file inside a container, as
	 * a zip, has no path of its own, so it goes to a temporary file first.
	 */
	private static OptionalLong findOffset(ByteProvider provider, InstructionSet isa)
			throws HereticusException, CancelledException, IOException {
		HereticusTool tool = new HereticusTool(HereticusTool.DEFAULT_EXECUTABLE);
		File file = provider.getFile();
		if (file != null && file.isFile() && file.length() == provider.length()) {
			return BaseSearch.find(tool, isa, file.toPath(), TaskMonitor.DUMMY);
		}
		Path copy = Files.createTempFile("hereticus", ".bin");
		try {
			try (InputStream bytes = provider.getInputStream(0)) {
				Files.copy(bytes, copy, StandardCopyOption.REPLACE_EXISTING);
			}
			return BaseSearch.find(tool, isa, copy, TaskMonitor.DUMMY);
		}
		finally {
			Files.deleteIfExists(copy);
		}
	}
}
