import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import analyzer as an


def types_of(text):
    return {i['violation_type'] for i in an.find_incidents(text)}


def incident(text, vtype):
    matches = [i for i in an.find_incidents(text) if i['violation_type'] == vtype]
    assert matches, f'Тип «{vtype}» не найден в: {text!r}'
    return matches[0]


# ── Банковская карта: Луна ───────────────────────────────────────────────────

def test_card_valid_luhn_detected():
    inc = incident('Оплата картой 4111 1111 1111 1111 прошла', 'Банковская карта')
    assert inc['severity'] == 'Критический'
    assert inc['count'] == 1


def test_card_invalid_luhn_ignored():
    assert 'Банковская карта' not in types_of('Номер заказа 4111 1111 1111 1112')


def test_card_multiple_counted():
    text = 'Карты: 4111 1111 1111 1111 и 5500 0000 0000 0004'
    inc = incident(text, 'Банковская карта')
    assert inc['count'] == 2
    assert 'совпадений: 2' in inc['detail']


# ── СНИЛС: контрольная сумма ─────────────────────────────────────────────────

def test_snils_valid_detected():
    assert 'СНИЛС' in types_of('СНИЛС сотрудника: 112-233-445 95')


def test_snils_invalid_checksum_ignored():
    assert 'СНИЛС' not in types_of('Число 112-233-445 96 не является СНИЛС')


# ── ИНН: контрольные разряды ─────────────────────────────────────────────────

def test_inn_valid_10_digit():
    assert 'ИНН' in types_of('ИНН 7707083893')


def test_inn_invalid_ignored():
    assert 'ИНН' not in types_of('ИНН 7707083894')


# ── Словарные (криминальные) паттерны: понижение одиночных совпадений ───────

def test_single_jargon_word_downgraded_to_medium():
    inc = incident('обсуждали откат', 'Коррупция / взятка')
    assert inc['severity'] == 'Средний'


def test_multiple_jargon_words_stay_critical():
    inc = incident('за взятку обещали откат', 'Коррупция / взятка')
    assert inc['severity'] == 'Критический'
    assert inc['count'] == 2


def test_generic_words_no_longer_match():
    assert not types_of('часовая зона изменилась, транзит грузов, наезд колеса на бордюр')


# ── Телефон и банковские реквизиты ───────────────────────────────────────────

def test_refund_notification_account_not_phone():
    text = ('Заявка на возврат денег №271188 принята.\n'
            'Сумма: 9240 ₽\nПолучатель: Станислав\n'
            'Номер счёта: 40817810238127574241\n'
            'БИК банка: 044525225\n'
            '№ заказа: 252175996')
    found = types_of(text)
    assert 'Телефон РФ' not in found      # «8…» внутри номера счёта — не телефон
    assert 'Номер счёта' in found         # падеж «счёта» распознаётся
    assert 'БИК банка' in found           # «БИК банка: …» распознаётся


def test_real_phone_still_detected():
    assert 'Телефон РФ' in types_of('Звоните: +7 (912) 345-67-89')
    assert 'Телефон РФ' in types_of('тел. 8 912 345 67 89')


# ── Прочие паттерны без регрессий ────────────────────────────────────────────

def test_password_detected():
    assert 'Пароль / секрет' in types_of('password: hunter22')


def test_passport_detected():
    assert 'Паспорт РФ' in types_of('паспорт 4509 123456')


def test_clean_text_no_incidents():
    assert an.find_incidents('Добрый день! Отчёт по продажам во вложении.') == []


# ── Вспомогательные функции ──────────────────────────────────────────────────

def test_extract_employee_skips_screenshot_words():
    emp, _ = an._extract_employee('Снимок экрана 2026-04-27 в 22.56.15.png')
    assert emp == 'Неизвестно'


def test_extract_employee_finds_name():
    emp, _ = an._extract_employee('ivanov_2026-04-27_22-56.png')
    assert emp == 'Ivanov'


def test_extract_employee_ignores_random_words():
    for name in ('pro-veb-klient-1s-2.png', 'interface-1c-41.png', 'i (1).webp'):
        emp, _ = an._extract_employee(name)
        assert emp == 'Неизвестно', name


def test_list_image_files_extensions_and_hidden(tmp_path):
    for name in ('a.png', 'b.webp', 'c.txt', '.DS_Store', 'd.JPG'):
        (tmp_path / name).write_bytes(b'')
    found = {os.path.basename(f) for f in an.list_image_files(str(tmp_path))}
    assert found == {'a.png', 'b.webp', 'd.JPG'}
