"""Remove repeated credential values, including mentions before the labelled field."""
import regex

MASK = "[секрет удалён]"


def mask_known_values(text, values):
    if not values:
        return text, 0
    pattern = regex.compile(r"\[секрет удалён\]|(?<!\w)\L<values>(?!\w)", values=values, cache_pattern=False)
    count = 0

    def replace(match):
        nonlocal count
        if match.group() != MASK:
            count += 1
        return MASK

    return pattern.sub(replace, text, timeout=15), count
