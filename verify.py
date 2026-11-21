#!/usr/bin/env python3
"""Bounded public checks with a separate explicit full-reproduction option.

All builds, regenerated scientific data and TeX auxiliaries use temporary storage.
Default: original-definition check through 24 and fresh producer/checker through 17.
--reproduce explicitly recomputes the published range 1..30 from source.
--tex rebuilds the monolithic manuscript PDF in scratch and checks byte identity.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def inventory(root=ROOT):
    root = Path(root)
    refs = {}
    for line in (root / 'checks.sha256').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        need(match is not None, 'checksum manifest syntax')
        h, name = match.groups()
        p = PurePosixPath(name)
        need(not p.is_absolute() and '..' not in p.parts and '\\' not in name
             and str(p) == name and name not in refs and name != 'checks.sha256',
             'unsafe/duplicate checksum path')
        refs[name] = h
    need(bool(refs), 'empty checksum manifest')
    actual = set()
    dirs = set()
    for p in root.rglob('*'):
        rel = p.relative_to(root).as_posix()
        if PurePosixPath(rel).parts[0] == '.git':
            continue  # Only root clone/worktree metadata has this exception.
        need(not p.is_symlink(), 'payload symlink: ' + rel)
        if p.is_dir():
            dirs.add(rel)
        else:
            need(p.is_file(), 'nonregular payload: ' + rel)
            actual.add(rel)
    need(actual == set(refs) | {'checks.sha256'},
         'changed inventory: ' + repr(sorted(actual ^ (set(refs) | {'checks.sha256'}))))
    expected_dirs = {parent.as_posix() for name in refs
                     for parent in PurePosixPath(name).parents if str(parent) != '.'}
    need(dirs == expected_dirs, 'unexpected/missing directory')
    for name, h in refs.items():
        need(sha(root / name) == h, 'checksum mismatch: ' + name)
        p = PurePosixPath(name)
        need(all(len(x) <= 8 for x in p.parts[:-1]), 'long directory: ' + name)
        need(name == '.gitignore' or p.suffix in {'.tex', '.c', '.py'} or len(p.stem.lstrip('.')) <= 8,
             'long ordinary basename: ' + name)
    return len(actual)


def rows(path, validation=False):
    result = []
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        need(len(parts) == (3 if validation else 2), 'table columns')
        need(all(re.fullmatch(r'0|[1-9][0-9]*', x) for x in parts[:2]), 'integer table')
        if validation:
            need(parts[2] == 'PASS', 'validation status')
        result.append(tuple(map(int, parts[:2])))
    need([n for n, _ in result] == list(range(1, len(result) + 1)), 'noncontiguous table')
    return result


def data(root=ROOT):
    root = Path(root)
    seq = rows(root / 'data/b180215.txt')
    need(len(seq) == 30 and seq[-1] == (30, 3209944), 'validated endpoint')
    need(seq == rows(root / 'runs/n30/res.tsv') == rows(root / 'runs/n30/val.tsv', True),
         'production/checker/canonical rows differ')
    baseline = rows(root / 'data/known24.txt')
    need(len(baseline) == 24 and seq[:24] == baseline, 'historical baseline')
    generated = (''.join(f'{n} {a}\n' for n, a in seq) + '\n').encode('ascii')
    need(generated == (root / 'data/b180215.txt').read_bytes(), 'b-file byte regeneration')
    for name in ['data/b180215.txt', 'data/known24.txt']:
        b = (root / name).read_bytes()
        need(b.endswith(b'\n\n') and not b.endswith(b'\n\n\n') and b'\r' not in b,
             'OEIS final blank line')
    state = json.loads((root / 'records/state.json').read_text())
    cfg = json.loads((root / 'runs/n30/cfg.json').read_text())
    done = json.loads((root / 'runs/n30/done.json').read_text())
    frozen = state['frozen_files']
    historical = state['scientific_files']
    need(cfg['N'] == 30 and cfg['source'] == sha(root / 'src/a180215.c')
         and cfg['makefile'] == sha(root / 'src/Makefile')
         and cfg['binary'] == frozen['src/a180215'], 'historical producer binding')
    for key, path in [('cfg', 'cfg.json'), ('res', 'res.tsv'), ('check', 'check.bin'), ('val', 'val.tsv')]:
        need(done[key] == sha(root / 'runs/n30' / path), 'completion binding: ' + key)
    need(done['status'] == 'VALIDATED' and done['F'] == historical['runs/n30/f.bin']
         and done['walk'] == historical['runs/n30/walk.bin'], 'historical completion binding')
    header = (root / 'runs/n30/check.bin').read_bytes()
    need(len(header) == 1056 and header[:8] == b'A215STAT'
         and hashlib.sha256(header[:-32]).digest() == header[-32:], 'terminal checkpoint digest')
    need(struct.unpack_from('<IIII', header, 8) == (2, 30, 30, 30)
         and int.from_bytes(header[24:32], 'little') == 0
         and int.from_bytes(header[56:64], 'little') == 0, 'terminal cursor')
    actual = state['actual']
    need(struct.unpack_from('<QQQ', header, 32) ==
         (actual['checker_states'], actual['checker_transitions'], actual['checker_peak_records']),
         'checkpoint work counters')
    answers = [int.from_bytes(header[64 + 16*i:80 + 16*i], 'little') for i in range(30)]
    need(answers == [a for _, a in seq], 'checkpoint answers')
    bindings = [done['cfg'], done['F'], done['res'], sha(root / 'check/state.cpp'),
                frozen['check/state'], done['walk']]
    need(header[576:768] == b''.join(bytes.fromhex(x) for x in bindings), 'checker identities')
    for phase, outcome in [('p01', 'PRODUCED_AUDITED'), ('v01', 'VALIDATED_STOP30')]:
        receipt = json.loads((root / f'records/{phase}/done.json').read_text())
        need(receipt['call_sha256'] == sha(root / f'records/{phase}/call.json')
             and receipt['outcome'] == outcome and receipt['native_work']['returncode'] == 0,
             'original execution receipt')
    # The manuscript's explicit example is a witness, never a coverage proof.
    x = (3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 2, 0, 0, 2, 1, 0, 0, 0, 1, 1, 5)
    witness = [sum(c*x[i+j] for j, c in enumerate((1, 4, 6, 4, 1))) for i in range(17)]
    need(witness == [3, 0, 1, 4, 7, 8, 9, 12, 13, 10, 11, 16, 14, 6, 2, 5, 15]
         and sorted(witness) == list(range(17)), 'manuscript witness')
    return seq


def call(argv, cwd, timeout=90, env=None):
    r = subprocess.run(list(map(str, argv)), cwd=cwd, capture_output=True,
                       text=True, timeout=timeout, env=env)
    need(r.returncode == 0, f'command failed: {argv!r}\n{r.stdout}\n{r.stderr}')
    return r.stdout


def regenerate(scratch, n, seq):
    """Fresh execution, with its own source/build/runtime bindings; no old state."""
    job = scratch / 'fresh'
    call([scratch / 'src/a180215', 'init', job, str(n)], scratch)
    call([scratch / 'src/a180215', 'next', job, '3000'], scratch, timeout=3060)
    call([scratch / 'check/state', 'next', job, '3000', '300'], scratch, timeout=3060)
    got = rows(job / 'res.tsv')
    need(got == seq[:n] == rows(job / 'val.tsv', True), 'fresh production/DP agreement')
    cfg = json.loads((job / 'cfg.json').read_text())
    done = json.loads((job / 'done.json').read_text())
    need(cfg['N'] == n and cfg['source'] == sha(scratch / 'src/a180215.c')
         and cfg['makefile'] == sha(scratch / 'src/Makefile')
         and cfg['binary'] == sha(scratch / 'src/a180215'), 'fresh build identity')
    need(done['status'] == 'VALIDATED', 'fresh terminal status')
    for key, name in [('cfg', 'cfg.json'), ('F', 'f.bin'), ('res', 'res.tsv'),
                      ('walk', 'walk.bin'), ('check', 'check.bin'), ('val', 'val.tsv')]:
        need(done[key] == sha(job / name), 'fresh completion digest: ' + key)
    generated = (''.join(f'{i} {a}\n' for i, a in got) + '\n').encode('ascii')
    expected = (''.join(f'{i} {a}\n' for i, a in seq[:n]) + '\n').encode('ascii')
    need(generated == expected, 'fresh b-file regeneration')


def bounded(root, seq, tex=False, reproduce=False):
    with tempfile.TemporaryDirectory(prefix='a215-public-') as tmp:
        scratch = Path(tmp)
        for d in ['src', 'check']:
            shutil.copytree(root / d, scratch / d)
        call(['make', '-C', scratch / 'src'], scratch)
        cpp = ['g++-13', '-O3', '-std=c++17', '-Wall', '-Wextra', '-Wpedantic',
               '-Wshadow', '-Wconversion', '-Wformat=2', '-Werror']
        call(cpp + ['check/state.cpp', '-o', 'check/state', '-lcrypto', '-ldl'], scratch)
        for exe in ['src/a180215', 'check/state']:
            need('SELFTEST PASS' in call([scratch / exe, 'selftest'], scratch), 'native selftest')
        call(['gcc-13', '-O3', '-std=c17', '-Wall', '-Wextra', '-Werror',
              'check/oracle24.c', '-o', 'oracle'], scratch)
        output = call([scratch / 'oracle'], scratch)
        parsed = [(int(n), int(v)) for n, v in
                  re.findall(r'^n=\s*(\d+) distinct_permutations=(\d+)$', output, re.M)]
        need(parsed == seq[:24], 'direct original-definition counts 1..24')
        cflags = ['gcc-13', '-O3', '-std=c17', '-Wall', '-Wextra', '-Wpedantic',
                  '-Wshadow', '-Wconversion', '-Wformat=2', '-Werror']
        call(cflags + ['check/review01.c', '-o', 'syntc', '-lcrypto', '-ldl'], scratch)
        call(cpp + ['check/review01.cpp', '-o', 'syntcpp', '-lcrypto', '-ldl'], scratch)
        (scratch / 'synthetic').mkdir()
        for exe in ['syntc', 'syntcpp']:
            need('SYNTHETIC_NOT_SEQUENCE' in call([scratch / exe, scratch / 'synthetic'], scratch),
                 'wide output fixture')
        if reproduce:
            need(shutil.disk_usage(scratch).free >= 16 * 1024**3,
                 'full reproduction requires at least 16 GiB free scratch space')
            available = re.search(r'^MemAvailable:\s+(\d+) kB$',
                                  Path('/proc/meminfo').read_text(), re.M)
            need(available and int(available[1]) * 1024 >= 12 * 1024**3,
                 'full reproduction requires at least 12 GiB available RAM')
        regenerate(scratch, 30 if reproduce else 17, seq)
        if tex:
            out = scratch / 'tex'
            out.mkdir()
            for _ in range(3):
                call(['pdflatex', '-no-shell-escape', '-interaction=nonstopmode',
                      '-halt-on-error', '-output-directory', out,
                      root / 'paper/A180215.tex'], scratch)
            log = (out / 'A180215.log').read_text(errors='replace')
            need(not re.search(r'^(?:[^\n]*\bWarning:|pdfTeX warning\b|(?:Over|Under)full\s+\\[hv]box|!)',
                               log, re.I | re.M)
                 and (out / 'A180215.pdf').read_bytes() == (root / 'paper/A180215.pdf').read_bytes(),
                 'TeX/PDF warnings or rebuild identity; use the documented TeX toolchain')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reproduce', action='store_true',
                   help='explicitly regenerate and validate all published terms 1..30')
    p.add_argument('--tex', action='store_true')
    a = p.parse_args()
    n = inventory()
    seq = data()
    bounded(ROOT, seq, a.tex, a.reproduce)
    print(json.dumps({'status': 'BOUNDED_PUBLIC_CHECK_PASS', 'files': n,
                      'canonical_range': [1, 30], 'direct_check_range': [1, 24],
                      'synthetic_wide_outputs': 'PASS (not sequence terms)',
                      'fresh_producer_and_coefficient_check_range': [1, 30 if a.reproduce else 17],
                      'private_archive_dependency': False,
                      'tex_pdf_check': a.tex,
                      'full_reproduction_executed': a.reproduce}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        raise SystemExit('STOP: ' + str(e))
