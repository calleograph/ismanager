from unittest.mock import patch

import pytest

from app.privacy import names, processing
from app.privacy.secrets import mask_explicit_fields, shadow
from app.privacy.known_values import MASK
from app.privacy.patterns import find_structured
from app.privacy.verify import independent_check


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


def test_wrapped_credentials_in_pdf_columns_and_free_text():
    source = ("        key=demo_api_b51b46e68359\n"
              "        f49a931c         Summary\n"
              "TKT-8   zz_demo_5c2d894b237a88    Signing secret\n"
              "        d602b44          Notes\n"
              "Other report: zz_demo_5c2d894b237a88d602b44.\n")
    result, count = mask_explicit_fields(source)
    assert count == 5 and "Summary" in result and "Notes" in result
    for fragment in ("b51b46e6", "f49a931c", "5c2d894", "d602b44"):
        assert fragment not in result
    policy = processing.policy_for("faceless")
    assert "secret" in independent_check(source, policy)
    assert independent_check(result, policy) == []


@pytest.mark.parametrize("suffix", ["uuudddd", "3987284"])
def test_wrapped_letter_or_digit_only_key_fragment(suffix):
    text = f"  key=monochromelabel\n  {suffix}     Summary\n  Report complete."
    result, _ = mask_explicit_fields(text)
    assert suffix not in result and "monochromelabel" not in result
    assert "Summary" in result and "Report complete." in result


@pytest.mark.parametrize("prefix", ["Wi-Fi password: ", "Authorization: Bearer ", "https://portal.invalid/?token="])
def test_completed_marker_does_not_block_verified_release(prefix):
    policy = processing.policy_for("faceless")
    assert independent_check(prefix + MASK, policy) == []
    assert "secret" in independent_check(prefix + "[SYNTHETIC_private_C42]", policy)


def test_internal_ticket_ids_without_number_sign():
    text = "Номер заявки: SKY-2099-0234. Инцидент ORB-ASR-2098-0056."
    observed = {text[f.start:f.end] for f in find_structured(text) if f.category == "doc_number"}
    assert observed == {"SKY-2099-0234", "ORB-ASR-2098-0056"}


def test_independent_detector_filter_preserves_matches_in_order():
    source = ("Адрес: г. Москва, ул. Примерная, д. 5\nuser@example.invalid\n"
              "СНИЛС 102-123-456 77. IP 192.0.2.13. Телефон +7 (901) 555-10-13. "
              "Срок действия 05/27. Паспорт 45 05 123456. Диагноз: астма.")
    complete = find_structured(source)
    assert {f.category for f in complete} >= {"email", "phone", "ip", "id_number", "bank", "health"}
    selected = {"email", "phone", "ip", "id_number", "bank"}
    assert find_structured(source, categories=selected) == [f for f in complete if f.category in selected]


def test_confusable_shadow_preserves_positions_and_abbreviations():
    text = "Иванов английский Password Pаssword рожденuя HTTPПароль КлючAPI"
    expected = "Иванов английский Password Password рождения HTTPПароль КлючAPI"
    assert shadow(text) == expected
    assert len(shadow(text)) == len(text)


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


@pytest.mark.skipif(not (names.NLP_DIR / names.NER_FILE).is_file(), reason="requires local NLP models")
def test_credential_detected_in_later_window_masks_earlier_unlabelled_copy(tmp_path):
    path = tmp_path / "log.txt"
    token = "novemberSyntheticIllustration"
    path.write_text("First occurrence " + token + "\n" + "Report processed.\n" * 850
                    + "Authorization: Bearer " + token + "\nFinal line.")
    result, _, _ = processing.redact_file(path, "txt")
    assert token not in result
    assert result.startswith("First occurrence ") and result.endswith("Final line.")
