# Terminal Interface

`--tui` compares the two binaries once, then lets you browse the report in
the terminal. You can sort it, filter it, and open the diff of each
function, with no second run:

```console
$ hereticus --tui fw-v1.elf fw-v2.elf
```

## The Functions

The first screen is the report, with the changed functions first. The
functions that are gone or new come after the pairs.

![The list of changed functions](./images/tui-functions.png)

- `s` changes the order, and `S` reverses it.
- `t` lists only the pairs that touched one kind of code, as `call`.
- `/` filters on the names. The letters must come in order, but need not
  be next to each other.
- `a` shows every function, `r` the pairs that changed only a constant,
  and `d` the data regions.
- `Enter`, or a second click, opens the diff of the selected function.

## The Diff

The diff shows the two bodies side by side, with the address of each
instruction. Red lines were removed, green lines were added, and yellow
lines changed only a value:

![The diff of one function, as assembly](./images/tui-diff.png)

`v` shows the same diff as IL statements, which read alike on each
architecture:

![The diff of one function, as IL](./images/tui-diff-il.png)

- `]` and `[` go to the next and the previous change.
- `v` changes between assembly and IL.
- `l` changes between two columns and one.
- `n` and `p` go to the next and the previous function.
- `Esc` goes back to the list.

## All Keys

`?` shows each key, on each screen.

| Key | In the list | In the diff |
|-----|-------------|-------------|
| `j` / `k` | down / up | down / up |
| `PgDn` / `PgUp` | a page down / up | a page down / up |
| `g` / `G` | first / last | top / bottom |
| `Enter` | open the diff | |
| `s` / `S` | next order / reverse the order | |
| `t` | next kind touched | |
| `a` / `r` / `d` | every function / retouched pairs / data regions | |
| `/` | filter the names | |
| `]` / `[` | | next / previous change |
| `v` | | assembly or IL |
| `l` | | side by side or one column |
| `n` / `p` | | next / previous function |
| `Esc` | | back to the list |
| `?` | this help | this help |
| `q` | quit, after a question | quit, after a question |

The mouse wheel scrolls, and a click selects a row.

The screenshots come from `book/tapes/tui.tape`. To make them again, run
`just tui-screenshots`. The tests of `hereticus-cli/src/tui/` lock the
text of each screen.
