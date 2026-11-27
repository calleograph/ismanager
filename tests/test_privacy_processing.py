from unittest.mock import patch

import pytest

from app.privacy import names, processing
from app.privacy.secrets import mask_explicit_fields


def test_ticket_fields_repeats_and_structured_values():
    text = ('before: corrected horse\nTicket HD-4\nПароль: corrected horse\n'
            'OTP: 18\n"client_secret": "escaped\\"secret", "status": "closed"\n'
            'secret: |\n  first-private-line\n  second-private-line\n'
            'public: preserved\nPIN: 0\n')
    masked, count = mask_explicit_fields(text)
    assert count == 6
    for value in ('corrected horse', '18', 'escaped', 'private-line', ': 0'):
        assert value not in masked
    assert '"status": "closed"' in masked and 'public: preserved' in masked
    assert mask_explicit_fields(masked) == (masked, 0)


def test_sections_preserve_every_character_and_reject_unbroken_overlimit():
    for text in ('ticket a ' * 5000, 'Заявка закрыта.\n' * 5000):
        chunks = list(processing.sections(text))
        assert len(chunks) > 1 and ''.join(chunks) == text
    with pytest.raises(processing.PrivacyError):
        list(processing.sections('x' * 60001))


@pytest.mark.skipif(not (names.NLP_DIR / names.NER_FILE).is_file(), reason="requires local NLP models")
def test_large_document_credentials_across_boundaries(tmp_path):
    file = tmp_path / 'helpdesk.txt'
    file.write_text('давний секрет описан как blue otter.\n' + 'Заявка обработана.\n' * 3300
                    + 'Пароль: blue otter\n'
                    + '-----BEGIN PRIVATE KEY-----\n' + 'UNPUBLISHED\n' * 1350
                    + '-----END PRIVATE KEY-----\nПользователь: Иван Петров.\n'
                    + 'Ответить по адресу example@sample.invalid.\nЗавершено.')
    result, stats, _ = processing.redact_file(file, 'txt')
    assert result.endswith('Завершено.')
    assert stats['secret'] >= 3 and 'example@' not in result and 'Петров' not in result
    assert not any(x in result for x in ('blue otter', 'UNPUBLISHED', 'PRIVATE KEY'))
    with patch.object(processing, 'independent_check', return_value=['secret']), pytest.raises(processing.PrivacyError):
        processing.redact_file(file, 'txt')
