# The demo at the top of the README: `just book-media`.
Output "book/src/images/demo.gif"
Set Shell bash
Set FontSize 15
Set Width 1100
Set Height 560
Set Padding 12
Set Framerate 12
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"
Hide
Type "export PATH=$PWD/target/x86_64-unknown-linux-musl/release:$PATH && cd fixtures/build/O2 && clear"
Enter
Show
Type "hereticus firmware.o firmware_v2.o"
Sleep 300ms
Enter
Sleep 3s
Type "hereticus --tui firmware.o firmware_v2.o"
Sleep 300ms
Enter
Sleep 1.5s
Enter
Sleep 1.5s
Type "]"
Sleep 1s
Type "]"
Sleep 1.2s
Type "v"
Sleep 2s
Escape
Sleep 800ms
Type "q"
Sleep 600ms
Enter
Sleep 500ms
