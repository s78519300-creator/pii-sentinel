from pii_sentinel.checksums import luhn_valid, verhoeff_check_digit, verhoeff_valid


def test_verhoeff_roundtrip():
    for base in ("23456789012", "99999999999", "51234567890"):
        assert verhoeff_valid(base + verhoeff_check_digit(base))


def test_verhoeff_detects_single_digit_error():
    good = "23456789012" + verhoeff_check_digit("23456789012")
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not verhoeff_valid(bad)


def test_verhoeff_detects_transposition():
    good = "23456789012" + verhoeff_check_digit("23456789012")
    swapped = good[0] + good[2] + good[1] + good[3:]
    assert not verhoeff_valid(swapped)


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert luhn_valid("5500-0000-0000-0004")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("12345")
