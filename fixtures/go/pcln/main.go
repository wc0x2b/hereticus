// Command pcln writes the function table of a Go ELF file, one
// "entry end name" a line in hexadecimal, for a test to use as the truth.
//
// garble replaces the magic number at the start of the table with one of
// its own, so that tools cannot find it, and patches the runtime to match.
// The rest of the table is the one the runtime reads, so pcln reads it
// with the usual magic put back.
package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
)

// The magic number of the function table of Go 1.20 and later.
const magic = 0xfffffff1

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pcln <Go ELF file>")
		os.Exit(2)
	}
	file, err := elf.Open(os.Args[1])
	check(err)
	section := file.Section(".gopclntab")
	if section == nil {
		check(fmt.Errorf("%s: no .gopclntab", os.Args[1]))
	}
	table, err := section.Data()
	check(err)
	file.ByteOrder.PutUint32(table, magic)
	text := file.Section(".text")
	if text == nil {
		check(fmt.Errorf("%s: no .text", os.Args[1]))
	}
	symbols, err := gosym.NewTable(nil, gosym.NewLineTable(table, text.Addr))
	check(err)
	if len(symbols.Funcs) == 0 {
		check(fmt.Errorf("%s: the function table lists no function", os.Args[1]))
	}
	for _, function := range symbols.Funcs {
		fmt.Printf("%x %x %s\n", function.Entry, function.End, function.Name)
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcln:", err)
		os.Exit(1)
	}
}
