from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import ClassVar, Iterable

__version__ = "0.2.0"

log = logging.getLogger(__name__)


class Misprinter:
    r"""
    You can use the `Misprinter` class to redact exact string matches or
    regular expressions within a string:

    >>> misprinter = Misprinter(
    ...     token=["my_secret_token", re.compile(r"^ghp_\w+")]
    ... )
    >>> assert misprinter.mask("this is my_secret_token") == "this is ****"
    >>> assert (
    ...     misprinter.mask("github tokens: ghp_abc123 ghp_def456")
    ...     == "github tokens: **** ****"
    ... )

    If you need to add a mask for new data to an existing instance then you
    can use the `add_mask_for` method:

    >>> misprinter = Misprinter()
    >>> assert misprinter.mask("a secret1234") == "a secret1234"

    >>> misprinter.add_mask_for("secret1234")
    >>> assert misprinter.mask("a secret1234") == "a ****"

    You can also initialise your `Misprinter` instance with
    `use_named_masks=True` if you would like to be able to identify what data
    has been masked more easily:

    >>> misprinter = Misprinter(use_named_masks=True)
    >>> misprinter.add_mask_for("another_secret", name="database password")

    >>> assert (
    ...     misprinter.mask("printing another_secret")
    ...     == "printing <'database password' (value removed)>"
    ... )
    """

    REPLACE_STR: ClassVar[str] = "*" * 4
    _UNWANTED: ClassVar[Iterable[str | re.Pattern[str]]] = frozenset(
        s for obj in ("", None) for s in (repr(obj), str(obj))
    )

    def __init__(
        self,
        *,
        use_named_masks: bool = False,
        **patterns: Iterable[str | re.Pattern[str]],
    ) -> None:
        super().__init__()
        self._redact_patterns = defaultdict(set)
        for k, vs in patterns.items():
            self._redact_patterns[k] = {v for v in vs if v and v not in self._UNWANTED}
        self._use_named_masks = use_named_masks

    def add_mask_for(self, data: str, name: str = "redacted") -> Misprinter:
        if data and data not in self._UNWANTED:
            log.debug("Adding %r to redacted patterns", name)
            self._redact_patterns[name].add(data)
        return self

    def mask(self, msg: str) -> str:
        if not isinstance(msg, str):
            log.debug(  # type: ignore[unreachable]
                "cannot mask object of type %s", type(msg)
            )
            return msg
        for mask, values in self._redact_patterns.items():
            repl_string = (
                self.REPLACE_STR
                if not self._use_named_masks
                else f"<{mask!r} (value removed)>"
            )
            for data in values:
                if isinstance(data, str):
                    msg = msg.replace(data, repl_string)
                elif isinstance(data, re.Pattern):
                    msg = data.sub(repl_string, msg)
        return msg


class MisprintFilter(Misprinter, logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # NOTE:
        # if we blindly mask all types, we will actually cast arguments to
        # log functions from external libraries to strings before they are
        # formatted into the message - for example, a dependency calling
        # log.debug("%d", 15) will raise a TypeError as this filter would
        # otherwise convert 15 to "15", and "%d" % "15" raises the error.
        # One may find a specific example of where this issue could manifest itself
        # here: https://github.com/urllib3/urllib3/blob/a5b29ac1025f9bb30f2c9b756f3b171389c2c039/src/urllib3/connectionpool.py#L1003  # noqa: E501
        # Anything which could reasonably be expected to be logged without being
        # cast to a string should be excluded from the cast here.
        record.msg = self.mask(record.msg)
        if record.args is None:
            pass
        elif isinstance(record.args, dict):
            record.args = {
                k: v if type(v) in (bool, int, float) else self.mask(str(v))
                for k, v in record.args.items()
            }
        else:
            record.args = tuple(
                arg if type(arg) in (bool, int, float) else self.mask(str(arg))
                for arg in record.args
            )
        return True
