# A180215: fourth-order binomial window sums

Carlo Corti — `carlo.corti@outlook.com`.

This source package accompanies *Permutations from Fourth-Order Binomial Window
Sums: OEIS A180215 through n=30*. It contains the reviewed monolithic manuscript,
exact production/validation sources, canonical results and essential small
execution records. Intermediate tables and journals are regenerated as needed.
Repository: `https://github.com/carcorti/A180215`.

Publication stage: **SOURCE PACKAGE — NO TAGGED RELEASE**.
Sources and data are provided on the repository's default branch.
Version `v1.0` and the date in `CITATION.cff` remain intended release metadata.
`10.5281/zenodo.xxxxxxxx` is an intentional DOI placeholder. The reviewed TeX v3
is preserved byte for byte, including its pre-publication availability wording.
No tagged release or Zenodo deposit is claimed. The first release and its
Zenodo publication are separate, explicitly authorized steps.

## Definition and coverage

For `n >= 1`, count ordered permutations `p` of `0,...,n-1` admitting `n+4`
nonnegative integers `x` with
`p[i] = x[i] + 4*x[i+1] + 6*x[i+2] + 4*x[i+3] + x[i+4]`.
Input entries may repeat; distinct reversals count separately. The forced zero
window determines the unique realization and gives the complementary-subset
formula proved in the manuscript.

`data/b180215.txt` contains exactly 30 consecutive decimal `n a(n)` rows from
1 through 30, followed by one empty final line. It matches the canonical
workspace file. `data/known24.txt` preserves Hardin's historical 1..24 baseline.
The six added values are:

| n | 25 | 26 | 27 | 28 | 29 | 30 |
|---|---:|---:|---:|---:|---:|---:|
| a(n) | 33572 | 50880 | 181968 | 464508 | 1150932 | 3209944 |

Zeros at 4..16 and the decrease from 444 at 20 to 420 at 21 are intentional.
The first uncomputed index is 31; source capacity 32 is separate from the
completed objective of 30.

## Essential contents

| Path | Reproduction or evidence role |
|---|---|
| `paper/A180215_v3.tex` | Reviewed monolithic manuscript with inline bibliography, no external figures or scientific includes |
| `src/a180215.c`, `src/Makefile` | Exact C17 producer and original compiler/linker flags |
| `check/state.cpp` | Separate C++17 weighted-state coefficient census and full ordered reduction |
| `check/oracle24.c` | Original-definition direct enumeration, fixed at 1..24; adapted from the MiniMax review contribution |
| `check/review01.c`, `check/review01.cpp` | Original output-only factorial fixtures for wide arithmetic and repeated finalization |
| `data/` | Canonical terms and historical comparison prefix |
| `runs/n30/` | Original configuration, result/validation tables, small terminal checkpoint and completion binding |
| `records/p01/`, `records/v01/` | Original invocation/completion receipts and performance measurements |
| `records/state.json`, `records/final.json` | Historical source, result, counter and integrity reconciliation |
| `records/tests.json` | Original direct-check and synthetic-fixture records, extracted with their parent receipt hash |
| `hist/` | Historical OEIS definition and entry chronology snapshots |
| `verify.py`, `checks.sha256` | Public source-based checks and exact payload inventory |
| `CITATION.cff`, `LICENSE` | Citation metadata and existing author-approved MIT license |

Scientific sources, Makefile, original numerical fixtures, data, manuscript and
retained run records preserve their original bytes. Publication container names
were shortened. Absolute paths and other inputs named inside old records are
historical provenance, not dependencies of the public commands. The small
terminal checkpoint contains final answers/counters, with no earlier frontiers.

The author retains a compressed service archive locally for optional inspection
of the original coefficient table and journal. It is excluded from this public
package, together with historical binaries, bundled system libraries and private
restore tools. The public route builds from source and generates its own data.
This package does not promise access to the exact original large-state bytes.

Private reviews, obsolete drafts/PDFs, forecasting/calibration debris, transport
duplicates and third-party papers are excluded. Bibliographic locators remain
in the manuscript. No extra a-file supplies distinct useful content beyond the
sequence tables and explicit manuscript witness; no certified sparse terms
beyond a gap exist.

## Dependencies and bounded verification

Use Linux x86-64, Python 3.11 or later (standard library), GNU Make, GCC/G++ 13
with unsigned 128-bit support, and installed OpenSSL development libraries.
The original environment used GCC/G++ 13.3.0 and OpenSSL 3.0.13. System libraries
are external dependencies. No previously generated scientific files are inputs.
Set `TMPDIR` to an existing suitable scratch filesystem when needed.

From the package root:

```bash
python3 -B verify.py
```

Expected result: `BOUNDED_PUBLIC_CHECK_PASS`, canonical range 1..30,
direct-check range 1..24 and fresh producer/coefficient-check range 1..17.

The driver rejects missing, changed, unexpected and unsafe payload files or
directories; only root `.git` clone/worktree metadata is excepted. It regenerates
the canonical b-file bytes from the result rows, reconciles the historical
validation tables, checkpoint answers/counters and execution bindings, and
checks the manuscript's n=17 witness by substitution.

It copies sources to temporary storage, runs the unchanged producer Makefile
and the checker compiler command recorded in `check/state.cpp`, then runs:

- both native self-tests;
- the direct original-definition check for all indices 1..24;
- the original synthetic wide-output fixtures (fabricated factorial rows);
- a fresh producer computation and full coefficient/ordered-sum check through
  17, comparing every regenerated row with the published prefix.

The fresh small case exercises the same production/validation route used for
the extension without private archives or old executables. The default command
does not recompute 25..30; those original results retain their execution evidence.
Hash reconciliation establishes byte identities, not a new enumeration.

For a two-pass draft-mode manuscript check:

```bash
python3 -B verify.py --tex
```

This also needs `pdflatex` and the packages in the TeX preamble (TeX Live, Latin
Modern, AMS, Babel, geometry, booktabs, microtype and hyperref). It produces no
PDF. Temporary builds, TeX auxiliaries and generated scientific data are removed
on completion or failure, leaving the frozen payload unchanged.

## Explicit reproduction of the extension

To regenerate and validate **all published terms 1..30** from source:

```bash
python3 -B verify.py --reproduce
```

This explicit expensive operation requires at least 12 GiB available RAM and
16 GiB free scratch space, following the original run's conservative admission
thresholds. The driver builds fresh executables, initializes an absent temporary
run root, and calls each numerical phase once. The native commands issued within
that temporary source tree are:

```text
src/a180215 init <fresh-root> 30
src/a180215 next <fresh-root> 3000
check/state next <fresh-root> 3000 300
```

It compares all generated result/validation rows with the canonical table,
regenerates the b-file bytes and verifies the fresh build and completion
bindings. Fresh executable/configuration hashes are their own identities, never
substitutes for historical ones. No original F table, journal, checkpoint,
archived binary or exact historical system library is needed.

Original producer/checker native wall times were approximately 30 and 110 seconds,
with peak RSS 6,717,906,944 and 977,747,968 bytes on an AMD Ryzen 9 7940HS.
These are historical measurements, not a runtime guarantee. The dense F table
has 8 GiB logical size. Native exit 75 means a partial invocation; exit 2 means
failure. The wrapper stops on any nonzero result or timeout, performs no retry,
and removes its disposable scratch data, including partial data. This one-shot
verification command does not provide campaign recovery or continuation.

Package preparation exercised the fresh path through 17 and the direct check
through 24; it did not repeat n=30 or extend the sequence further. The producer
and separate checker share the zero-anchor theorem and kernel while differing
in traversal, state layout, accumulation and reduction. No original-definition
direct enumeration is claimed at 25..30.
