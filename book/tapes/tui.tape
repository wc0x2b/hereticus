# Make the screenshots of the TUI page: `just tui-screenshots`.
Output "/tmp/hereticus-tui.gif"
Set Shell bash
Set FontSize 16
Set Width 1400
Set Height 520
Set Padding 10
Set Theme "Catppuccin Mocha"
Hide
Type "export PATH=$PWD/target/x86_64-unknown-linux-musl/release:$PATH && clear"
Enter
Show
Type "hereticus --tui fixtures/build/O2/firmware.o fixtures/build/O2/firmware_v2.o"
Enter
Sleep 1s
Screenshot "book/src/images/tui-functions.png"
Enter
Sleep 500ms
Screenshot "book/src/images/tui-diff.png"
Type "v"
Sleep 500ms
Screenshot "book/src/images/tui-diff-il.png"
Type "q"
Sleep 300ms
Type "y"
