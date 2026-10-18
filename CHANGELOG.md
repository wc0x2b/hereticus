# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/wc0x2b/hereticus/releases/tag/v0.1.0) - 2026-10-18

### Fixed

- fixup! Make the README short

### Other

- Read the one doc of the stub example with no loop, as clippy asks
- Keep the README short, and put the details in the book only
- Add a motto to the README, and remove a stray tag at its end
- Read a zero AArch64 word as padding
- End the command quietly when the reader closes the pipe
- Build x86-64 and i686 backports, and test x86 against them
- Find and compare functions in x86-64 and 32-bit x86 code
- Decode NEON, VFPv4 and the A32 words yaxpeax refuses
- Document the Ghidra extension
- Test the Ghidra extension in headless Ghidra
- List the functions of one binary with --functions
- Time hereticus, radiff2 and Ghidra on each backport pair
- Add a book page that compares hereticus with radiff2 and Ghidra
- Check the comparison against Ghidra, and rank ties as a reader reads them
- Check the comparison against radiff2 and Ghidra on the backports
- Bring the reports up to date with the tool, and tag their ranks
- Check the outputs that the reports show
- Check the outputs and the numbers of the README and the book
- Read the literal pools of MIPS16e code as data
- Read the tables and pools of addresses in MIPS16e code as data
- Add the MIPS16e builds of the older libubox and uhttpd fixes
- Add the libubox and uhttpd fixes of OpenWrt 18.06 and 19.07 as published fixes
- Count a check before an early exit as five instructions added
- Rank first a call turned into its bounded form
- Name the PLT stubs of a MIPS16e executable
- Add a Malware section to the book, with two builds of Mirai for ARM
- Add the procd and jsonfilter fixes of OpenWrt 24.10.6 as published fixes
- Add an mdbook with usage, examples and real-life examples
- Read the two ways MIPS loads an address alike, and pair stubs by import
- Read a stripped kernel module, and add the ltq-ptm fix of CVE-2025-62525
- Name the calls of an unlinked object by their relocations in the IL view
- Add the scp fix of CVE-2026-35385 in dropbear as a published fix
- Add the odhcpd fix of CVE-2026-53921 as a published fix
- Add the uhttpd fix of CVE-2026-55614 as a published fix
- Add the dropbear fix of CVE-2025-14282 as a published fix
- Pair functions by their slot in a vtable or a table of handlers
- Stop re-exporting other crates from hereticus-arch
- Move the Recovery half of each architecture into hereticus-recovery
- Remove scratch examples, and add a recipe to publish the workspace
- Split hereticus into crates, each with one job
- Box the diff a screen of the TUI holds
- Decide by opcode in the AArch64 reading of whole functions
- Take no pair by similarity where a rival ranks as high
- Keep close pairs whole, and sort rescheduled code last
- Use mimalloc so the musl build serves its threads at once
- Pair two functions by a text or constant only they hold
- Lock the kernel pairs and the fix ranks against the truth
- Name the alignment a NEON load or store asserts
- Name the function in the same place as a gone or new one
- Pair functions by their place between pairs
- List --sort rare in the README
- Align a large function by anchors, not by position
- Add --sort rare: weigh an addition by how few pairs share it
- Show the making of the global pointer as one IL line, and no it
- Name a call to a stripped function as its pair is named
- Show the condition of an A32 return, as `bxne lr`
- Keep the TUI fast on a kernel of many thousand functions
- Ask before the TUI quits, as heretek does
- Lighten the grays of the TUI, as heretek does
- Filter the TUI by fuzzy name and by the kind touched
- Use the mouse in the TUI
- Jump between the changes of a TUI diff, and show addresses
- List the functions gone and new in the TUI
- Style the TUI as heretek does
- Browse the report in the terminal with --tui
- Show an access to a list of registers as one IL load or store
- Print what A32 and AArch64 instructions use, and read conditional compares
- Show a constant of an address as one in the IL view
- Name what the IL view points at and calls
- Show the IL view in the README and two reports
- Show a diff as IL statements with --view il
- Show the reports in the documents as markdown tables
- Print the report as markdown or as JSON
- Read an ELF file that sstrip left, and report CVE-2025-62526
- Read stripped and raw MIPS16e libraries
- Read MIPS16e functions in a MIPS binary
- Read a fileset kernelcache kext by kext
- Unpack firmware images, so a user need not extract the code first
- Add --diff-all, the diff of every changed function in one run
- Show the report the README example gives today, and update the TODOs
- Lift the MIPS32 words, and read a compare one way whatever took it
- Read an idiom as the plain operation it computes
- Read each operand from the IL, not from its printed text
- Lift A32, Thumb-2 and MIPS32 too, and read every compare one way
- Sort the report by the instructions added, first
- Link the real-life reports from the README
- Read AArch64 Mach-O, as macOS and iOS ship it
- Build and measure Cortex-M firmware, and fix what it found
- Read a library that mixes A32 and Thumb-2 function by function
- Read NEON loads and stores, and name the rest of NEON
- Read AArch64
- Read Thumb-2 code
- End a function at a tail call, and pair the twins that exposes
- Report a changed text
- Build the backports with GCC and at every level, and fix what it found
- Find exact function ranges in stripped and raw C++ code
- Report a call that reaches a different function
- Hide data regions that go or come
- Stop two more false function starts on MIPS
- Find the functions that data hid in a raw image
- Split raw ARM images less
- Correct the README
- Do not skip code that a branch reaches to find a prologue
- Check a MIPS load address with jal targets
- Recover stripped ARM and MIPS functions as a linker lays them out
- Hide MIPS regions that hold data rather than code
- Stop reporting moved MIPS code as changed values
- Keep the nop in the last MIPS delay slot
- Show the current OpenWrt stub report in the README
- Test real OpenWrt firmware on ARM and MIPS
- Test the command line on raw MIPS images
- Show ELF files and firmware in the README
- Rename to hereticus, and build the fixtures in a container
- Add a firmware fixture pair, and `just run` to compare it
- Keep the TOUCHED column quiet when it repeats CHANGE
- Name what kind of code an edit touched in the report
- Note the AI assistance in the README
- Make the README short
- Rename the project to heresy
- Rename the project to tech-heresy
- Sort the report by how much a function changed
- Show the instruction diff of one function
- Draw the report as a table and color what changed
- Hold back the functions that only changed a constant
- Record the progress bar and the measured speed
- Stop cutting functions apart at every return
- Do not call byte-different code unchanged
- Record a trial against a real kernel patch
- Read raw firmware images with an explicit load address
- Record the constants finding and the firmware workflow in the README
- Update README for stripped binary support
- Add the command line tool
- Add README
