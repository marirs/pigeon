# Fuzzing

Five targets over the code that consumes untrusted bytes: the SMTP command
parser, the two stream framers, the address validator, and the delivery client
against a server that answers with anything at all.

This is a separate workspace on purpose. `libfuzzer-sys` needs nightly and a
sanitizer runtime; making the stable CI gates depend on that would trade gates
that always run for gates that sometimes can.

## Running

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cd fuzz
RUSTUP_TOOLCHAIN=nightly cargo fuzz run command_parse -- -max_total_time=300
```

Targets: `command_parse`, `data_reader`, `line_reader`, `address_parse`,
`delivery_client`.

## What the targets assert

Not "does not panic". A target that only catches crashes would have found
nothing here — both real bugs below were memory-safe and returned successfully.

| Target | Property |
|---|---|
| `command_parse` | Deterministic; no value it returns carries CR, LF or NUL |
| `data_reader` | Chunk boundaries cannot change the body; the size cap holds |
| `line_reader` | Chunk boundaries cannot change framing; one LF per line, at the end |
| `address_parse` | Accepted addresses are resolvable and safe to interpolate; `Display` round-trips; mailbox identity depends only on the local part |
| `delivery_client` | Survives any reply stream; nothing a remote server says reaches a log unescaped |

The differential properties matter more than the crash checks. A terminator
split across two reads is the bug class this codebase has already been bitten
by twice, and it is precisely what an example-based test cannot cover — the
author picks the splits they thought of.

## Corpus

`seeds/` is committed and holds two things: hand-written starting points, and
every input that has ever crashed a target. `corpus/` is generated and ignored.

Seed a run with:

```bash
RUSTUP_TOOLCHAIN=nightly cargo fuzz run <target> seeds/<target> -- -max_total_time=300
```

## What fuzzing found on its first run

- **`command_parse`, within seconds.** `strip_terminator` removes only the
  *trailing* CRLF, so `EHLO mail.example.com\ri` produced a greeting holding a
  bare CR — the header-injection primitive `Address::parse` had been hardened
  against, and that the greeting had been hardened against *at the header* one
  round earlier. Fixed at the parser, where the guarantee belongs: a `Command`
  can no longer hold one, and the header sanitiser stays as the second layer.

- **`delivery_client`.** A receiving server's reply text is carried into
  `Accepted::message` and logged with `Display`. `trim_end_matches` strips only
  the end, so `250ME\r2` reached the log with its CR intact — letting whatever
  answers on port 25 forge entries in Pigeon's log. Reply text is now
  sanitised and bounded.

- **`line_reader`, a wrong assertion rather than a bug.** The target asserted
  framed lines hold no LF, which is what the module docstring implied
  ("CRLF-delimited"). The code splits on LF and keeps it, and always has. The
  code was right, the docstring had never matched it, and the assertion was
  written from the docstring.

Three findings, two of them the same mistake the codebase had already made
twice under different names, and none of them reachable by a test somebody sat
down to write.
