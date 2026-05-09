# Iter 042 — Green: __version__ + --version + py.typed

## Cosa è stato fatto

### `src/malphas/__init__.py`

Sostituito `__version__ = "0.2.0"` hardcoded con lookup a runtime:

```python
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("malphas")
except PackageNotFoundError:
    __version__ = "0+unknown"
```

Niente più drift tra `pyproject.toml` e un constant interno.

### `src/malphas/__main__.py`

Aggiunto `parser.add_argument("--version", action="version",
version=f"malphas {__version__}")`. Il flag stampa la versione e
exit(0) prima del prompt passphrase.

### `src/malphas/py.typed`

File vuoto (marker PEP 561). Indica che il package fornisce type
annotations native — i consumer downstream possono usare mypy/pyright
contro malphas senza dipendere da type stubs separati.

### `pyproject.toml`

Aggiunto `[tool.hatch.build.targets.wheel.force-include]` per
includere `py.typed` nelle wheel build (hatch by default ignora i
file non-`.py`).

### Closes

Iter-001 finding **C7**: "`__init__.py` exposed an obsolete hardcoded
`__version__`". Ora dinamico.

## Verifica

```
$ pip install -e .
$ python -m malphas --version
malphas 0.5.6
$ python -c "from malphas import __version__; print(__version__)"
0.5.6
```

## Versioning

Patch 0.5.6 → 0.5.7 (user-visible quality of life + closing review item).

## Smoke gates

- ruff: clean
- mypy: clean (21 file)
- bandit: 0 findings
- pytest focused subset (72 test): green
