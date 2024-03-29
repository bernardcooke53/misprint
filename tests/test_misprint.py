import io
import logging
import random
import re
import string
from logging import LogRecord

import pytest

from misprint import Misprinter, MisprintFilter

random.seed(0)


def _random_string(length: int = 10) -> str:
    alphabet = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
    )
    return "".join(random.choice(alphabet) for _ in range(length))


@pytest.fixture
def default_misprinter():
    yield Misprinter()


@pytest.fixture
def default_misprint_filter():
    yield MisprintFilter()


@pytest.fixture
def logging_output_stream():
    return io.StringIO()


@pytest.fixture
def logger(logging_output_stream, default_misprint_filter):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(logging.StreamHandler(logging_output_stream))
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    for h in root.handlers:
        h.addFilter(default_misprint_filter)

    return log


@pytest.mark.parametrize("unwanted", [repr(""), repr(None), "", str(None)])
def test_unwanted_masks_not_applied(default_misprinter, unwanted):
    default_misprinter.add_mask_for(unwanted, "foo")
    assert default_misprinter._redact_patterns["foo"] == set()

    test_str = f"A long string containing the unwanted {unwanted} data"
    assert default_misprinter.mask(test_str) == test_str


@pytest.mark.parametrize(
    "masked, secret",
    [
        ("secret-token", "secret-token"),
        (re.compile(r"ghp_.+?(?=\s|$)"), "ghp_" + _random_string(15)),
    ],
)
@pytest.mark.parametrize("use_named_masks", (True, False))
def test_mask_applied(use_named_masks, masked, secret):
    misprinter = Misprinter(use_named_masks=use_named_masks)
    misprinter.add_mask_for(masked, "secret")
    test_str = "Your secret is... {secret} preferably hidden"

    assert misprinter.mask(test_str.format(secret=secret)) == test_str.format(
        secret="<'secret' (value removed)>"
        if use_named_masks
        else misprinter.REPLACE_STR
    )


_secrets = (
    "token" + _random_string(),
    "token" + _random_string(),
    "secret" + _random_string(),
    "secret" + _random_string(),
)


@pytest.mark.parametrize(
    "masked, secrets",
    [
        (_secrets, _secrets),
        ((re.compile(r"token.+?(?=\s|$)"), re.compile(r"secret.+?(?=\s|$)")), _secrets),
    ],
)
def test_multiple_secrets_with_same_mask(masked, secrets):
    misprinter = Misprinter(use_named_masks=True)

    for mask in masked:
        misprinter.add_mask_for(mask, "ksam")

    test_str = " ".join(secrets)

    assert misprinter.mask(test_str) == " ".join(
        "<'ksam' (value removed)>" for _ in secrets
    )


def test_secrets_exact_replacement():
    misprinter = Misprinter(use_named_masks=True)
    for secret in _secrets:
        misprinter.add_mask_for(secret, "smak")

    test_str = ", ".join(_secrets) + "!"
    assert (
        misprinter.mask(test_str)
        == ", ".join("<'smak' (value removed)>" for _ in _secrets) + "!"
    )


@pytest.mark.parametrize(
    "rec",
    [
        LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            args=(_secrets[3],),
            msg="long message with format %s for secret",
            exc_info=None,
        ),
        LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            args={"secret1": _secrets[1], "secret2": _secrets[2]},
            msg="another message using %(secret1)s and %(secret2)s",
            exc_info=None,
        ),
    ],
)
@pytest.mark.parametrize(
    "masked", (_secrets, (re.compile(r"(secret|token).+?(?=\s|$)"),))
)
def test_log_record_is_masked_with_simple_args(default_misprint_filter, rec, masked):
    for mask in masked:
        default_misprint_filter.add_mask_for(mask)

    if isinstance(rec.args, tuple):
        assert rec.msg % tuple(
            default_misprint_filter.REPLACE_STR for _ in rec.args
        ) == default_misprint_filter.mask(rec.getMessage())
    elif isinstance(rec.args, dict):
        assert rec.msg % {
            k: default_misprint_filter.REPLACE_STR for k in rec.args.keys()
        } == default_misprint_filter.mask(rec.getMessage())


@pytest.mark.parametrize(
    "rec",
    [
        LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            args=(_secrets,),
            msg="long message with format %s for secrets",
            exc_info=None,
        ),
        LogRecord(
            name=__name__,
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            args={"secret1": _secrets[1], "other": _secrets[2:]},
            msg="another message using %(secret1)s and %(other)r",
            exc_info=None,
        ),
    ],
)
@pytest.mark.parametrize(
    "masked", (_secrets, (re.compile(r"(secret|token).+?(?=\s|$)"),))
)
def test_log_record_is_masked_with_nontrivial_args(
    default_misprint_filter, rec, masked
):
    for mask in masked:
        default_misprint_filter.add_mask_for(mask)

    assert any(secret in rec.getMessage() for secret in _secrets) and all(
        secret not in default_misprint_filter.mask(rec.getMessage())
        for secret in _secrets
    )


@pytest.mark.parametrize(
    "log_level",
    (
        logging.DEBUG,
        logging.INFO,
        logging.WARNING,
        logging.ERROR,
        logging.CRITICAL,
    ),
)
def test_log_messages_are_masked(
    default_misprint_filter, log_level, logging_output_stream, logger
):
    for secret in _secrets:
        default_misprint_filter.add_mask_for(secret)

    root = logging.getLogger()
    logger.log(log_level, ", ".join("%s" for _ in _secrets), *_secrets)
    for h in (*root.handlers, *logger.handlers):
        h.flush()

    written = logging_output_stream.getvalue()
    assert all(secret not in written for secret in _secrets)


@pytest.mark.parametrize("obj", (object(), (), {}, AttributeError("whoopsie")))
def test_non_strings_are_returned(default_misprint_filter, obj):
    rec = LogRecord(
        name=__name__,
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        args=(),
        msg=obj,
        exc_info=None,
    )

    assert default_misprint_filter.mask(rec.getMessage()) == str(obj)
