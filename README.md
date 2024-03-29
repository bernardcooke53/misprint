# misprint

[![PyPI - Version](https://img.shields.io/pypi/v/misprint.svg)](https://pypi.org/project/misprint)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/misprint.svg)](https://pypi.org/project/misprint)

An integration with the Python standard library's [logging module](https://docs.python.org/3/library/logging.html)
that masks secrets in log messages before they are emitted. This project
was heavily inspired by an excellent [blog post](https://relaxdiego.com/2014/07/logging-in-python.html)
which has been updated/adapted for modern Python versions.

Misprint is fully type-annotated for easier integration with [mypy](https://mypy.readthedocs.io/en/stable/).

---

## **Table of Contents**

- [Installation](#installation)
- [License](#license)
- [Usage](#usage)
  - [`misprint.Misprinter`](#misprintmisprinter)
  - [standard library logging integration](#misprintmisprintfilter)

## Installation

```console
pip install misprint
```

## License

`misprint` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html)
license.

## Usage

### `misprint.Misprinter`

You can use the `Misprinter` class to redact exact string matches or regular expressions
within a string:

```python
misprinter = Misprinter(token=["my_secret_token", re.compile(r"^ghp_\w+")])

assert misprinter.mask("this is my_secret_token") == "this is ****"
assert (
    misprinter.mask("github tokens: ghp_abc123 ghp_def456")
    == "github tokens: **** ****"
)
```

If you need to add a mask for new data to an existing instance then you can use the
`add_mask_for` method:

```python
misprinter = Misprinter()
assert misprinter.mask("a secret1234") == "a secret1234"

misprinter.add_mask_for("secret1234")
assert misprinter.mask("a secret1234") == "a ****"
```

You can also initialise your `Misprinter` instance with `use_named_masks=True`
if you would like to be able to identify what data has been masked more easily:

```python
misprinter = Misprinter(use_named_masks=True)
misprinter.add_mask_for("another_secret", name="database password")

assert (
    misprinter.mask("printing another_secret")
    == "printing <'database password' (value removed)>"
)
```

### `misprint.MisprintFilter`

`misprint` also provides a `logging.Filter` subclass, which integrates with the
Python standard library's `logging` module to enable redaction of log messages.

`MisprintFilter` is a subclass of `Misprinter`, so inherits all of the methods
detailed above. This is useful, as the filter can be connected to the loggers
that are configured for a program at startup, and new secrets can be
conveniently added to the filter to be redacted in the logs:

```python
import logging
import sys

import misprint

logging.basicConfig(
    datefmt="[%X]",
    handlers=[logging.StreamHandler(sys.stderr)],  # plus others
)

misprinter = misprint.MisprintFilter()

for handler in logging.getLogger().handlers:
    handler.addFilter(misprinter)

A_TOKEN = "asdf1234"

misprinter.add_mask_for(A_TOKEN)

log.error("Bad token: %s", A_TOKEN)
```
