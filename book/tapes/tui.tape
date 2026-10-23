# Make the screenshots of the TUI page: `just book-media`.
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
# A key right after a screenshot can reach it first.
Sleep 500ms
Enter
Sleep 500ms
Screenshot "book/src/images/tui-diff.png"
Sleep 500ms
Type "v"
Sleep 500ms
Screenshot "book/src/images/tui-diff-il.png"
Sleep 500ms
Escape
Type "Gm"
Sleep 300ms
Type "auth bypass"
Sleep 500ms
Screenshot "book/src/images/tui-label.png"
Sleep 500ms
Enter
Sleep 500ms
Screenshot "book/src/images/tui-marked.png"
Sleep 500ms
# Save out of the tree, so the tape leaves no file behind.
Type "w"
Sleep 300ms
Backspace 60
Type "/tmp/hereticus-tui.hereticus.json"
Enter
Sleep 300ms
Type "q"
Sleep 300ms
Enter
