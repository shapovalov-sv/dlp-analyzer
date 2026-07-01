import re
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from PIL import Image

OCR_TIMEOUT = 30  # seconds per file

# ── Patterns: (type, regex, severity, describe_lambda) ─────────────────────
PATTERNS = [

    # ════════════════════════════════════════════════════════════════════════
    # КРИТИЧЕСКИЙ — немедленная реакция
    # ════════════════════════════════════════════════════════════════════════

    (
        'Банковская карта',
        r'\b(?:\d[ \-]?){15,16}\b',
        'Критический',
        lambda m: f'Карта: {m[:4]}****{m[-4:] if len(m) >= 8 else ""}',
    ),
    (
        'Номер счёта',
        r'(?i)(?:счёт|счет|р/с|р\.с\.|расчётный)[\s:№]*(\d{20})',
        'Критический',
        lambda m: f'Счёт: {m[:4]}...{m[-4:]}',
    ),
    (
        'СНИЛС',
        r'\b\d{3}[\-\s]\d{3}[\-\s]\d{3}[\-\s]\d{2}\b',
        'Критический',
        lambda m: f'СНИЛС: {m[:3]}-***-***',
    ),
    (
        'Паспорт РФ',
        r'\b\d{4}\s\d{6}\b',
        'Критический',
        lambda m: f'Паспорт: {m[:4]} ******',
    ),
    (
        'Полис ОМС / ДМС',
        r'(?i)(?:полис|ОМС|ДМС|страховой\s+полис)[\s:№]*(\d{16})',
        'Критический',
        lambda m: f'Полис: {m[:4]}****{m[-4:]}',
    ),
    (
        'Пароль / секрет',
        r'(?i)(?:password|пароль|passwd|pwd|secret|token|ключ|кодовое\s+слово)\s*[:=]\s*\S{4,}',
        'Критический',
        lambda m: 'Найдена строка с паролем или токеном',
    ),
    (
        'API-ключ',
        r'(?i)(?:api[_\-]?key|bearer|authorization|x\-api\-key|access[_\-]?token|private[_\-]?key)\s*[:=]\s*[A-Za-z0-9\-_.+/]{20,}',
        'Критический',
        lambda m: 'Найден API-ключ или токен авторизации',
    ),
    (
        'SSH / PGP ключ',
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'Критический',
        lambda m: 'Найден приватный SSH/PGP ключ',
    ),
    (
        'Криптовалютный кошелёк',
        r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[a-fA-F0-9]{40}\b',
        'Критический',
        lambda m: f'Крипто-кошелёк: {m[:8]}...{m[-4:]}',
    ),
    (
        'БИК банка',
        r'(?i)(?:БИК|BIK)[\s:]*(\d{9})',
        'Критический',
        lambda m: f'БИК: {m[:3]}***{m[-3:]}',
    ),

    # ── Криминальный риск ────────────────────────────────────────────────────
    (
        'Коррупция / взятка',
        r'(?i)(?:'
        r'\bвзятк[аиу]\b'               # взятка / взятки / взятку
        r'|\bвзяточни(?:к|чество)\b'    # взяточник / взяточничество
        r'|\bоткат(?:ы|ов|е|ная)?\b'    # откат / откаты / откатная схема
        r'|\bподкуп\b'
        r'|\bкоррупц(?:ия|ии|ионн)\b'   # коррупция / коррупционный
        r'|\bкоррупционн\w+'
        r'|\bдача\s+взятки\b'
        r'|\bполучение\s+взятки\b'
        r'|\bзанос\b'                   # жаргон: «занос» = взятка
        r'|\bзаносить\b'
        r'|\bоткатить\b'
        r'|\bоткатная\b'
        r'|\bнезаконное\s+вознаграждение\b'
        r')',
        'Критический',
        lambda m: f'Коррупция / взятка: «{m.strip()}»',
    ),
    (
        'Обналичивание / отмывание',
        r'(?i)(?:'
        r'\bобнал\b'                     # обнал
        r'|\bобналич(?:ить|ивание|ка)\b' # обналичить / обналичивание
        r'|\bобнальщик\b'
        r'|\bотмывание\b'
        r'|\bотмыв(?:ать|ать\s+деньги)\b'
        r'|\bлегализац(?:ия|ии)\s+(?:доход|денег|средств)\b'
        r'|\bчёрная\s+касса\b'
        r'|\bчёрная\s+бухгалтери\b'
        r'|\bтеневая\s+зарплат\b'        # теневая зарплата
        r'|\bсерая\s+зарплат\b'          # серая зарплата
        r'|\bзарплата\s+в\s+конверте\b'
        r'|\bнеучтённый\s+нал\b'
        r'|\bналичка\s+мимо\s+кассы\b'
        r'|\bдроппер\b'                  # дроп-мул
        r'|\bдроп(?:-\s*мул)?\b'
        r'|\bтранзит(?:ная\s+схема)?\b'
        r'|\bфиктивн\w+\s+(?:сделк|договор|контракт)\b'
        r'|\bподставн\w+\s+фирм\b'       # подставная фирма
        r'|\bоднодневка\b'               # фирма-однодневка
        r')',
        'Критический',
        lambda m: f'Обнал / отмывание: «{m.strip()}»',
    ),
    (
        'Криминальная активность',
        r'(?i)(?:'
        r'\bмошенничество\b'
        r'|\bхищение\b'
        r'|\bрастрат[аы]\b'              # растрата / растраты
        r'|\bвымогательство\b'
        r'|\bвымогать\b'
        r'|\bшантаж\b'
        r'|\bшантажировать\b'
        r'|\bрейдерств\b'                # рейдерство
        r'|\bкрышевание\b'
        r'|\bкрышевать\b'
        r'|\bнаезд\b'                    # жаргон: силовое давление
        r'|\bслить\s+базу\b'             # слить базу данных
        r'|\bслить\s+данные\b'
        r'|\bпробить\s+по\s+базе\b'      # незаконный запрос по базам
        r'|\bкупить\s+справку\b'
        r'|\bкупить\s+(?:диплом|права|документ)\b'
        r'|\bпальцы\s+вверх\b'           # жаргон угрозы
        r'|\bчёрный\s+нал\b'
        r'|\bналик\b'                    # жаргон: наличные вне кассы
        r'|\bкидалово\b'
        r'|\bкинуть\s+(?:партнёр|фирм|компани)\b'
        r')',
        'Критический',
        lambda m: f'Криминальная активность: «{m.strip()}»',
    ),
    (
        'Уголовный / правовой риск',
        r'(?i)(?:'
        r'\bуголовн\w+\s+дел\b'          # уголовное дело
        r'|\bст(?:атья|\.)\s*\d+\s*УК\b' # ст. 290 УК / статья 159 УК
        r'|\bУК\s+РФ\s+ст\b'
        r'|\bч\.\s*\d+\s+ст\.\s*\d+\s+УК\b'
        r'|\bпривлечь\s+к\s+ответственности\b'
        r'|\bвозбуждение\s+дела\b'
        r'|\bследственный\s+комитет\b'
        r'|\b(?:обыск|выемка|арест\s+счет)\b'
        r'|\bследователь\b'
        r'|\bдопрос\b'
        r'|\bпод\s+следствием\b'
        r'|\bпод\s+стражей\b'
        r'|\bсрок\s+(?:получить|дать|лет)\b'  # «получить срок»
        r'|\bзона\b'                     # жаргон: тюрьма
        r'|\bпосадить\b'                 # жаргон: посадить в тюрьму
        r'|\bконвертная\s+схема\b'
        r')',
        'Критический',
        lambda m: f'Уголовный риск: «{m.strip()}»',
    ),

    # ════════════════════════════════════════════════════════════════════════
    # СРЕДНИЙ — важно, требует проверки
    # ════════════════════════════════════════════════════════════════════════

    (
        'ИНН',
        r'(?i)ИНН[\s:]*(\d{10,12})',
        'Средний',
        lambda m: f'ИНН: {m[:4]}******',
    ),
    (
        'ОГРН / КПП',
        r'(?i)(?:ОГРН|КПП|ОГРНИП)[\s:]*(\d{9,15})',
        'Средний',
        lambda m: f'ОГРН/КПП: {m[:4]}...{m[-3:]}',
    ),
    (
        'SWIFT / корр. счёт',
        r'(?i)(?:SWIFT|БИК\s*SWIFT|свифт)[\s:]*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)',
        'Средний',
        lambda m: f'SWIFT-код: {m}',
    ),
    (
        'Телефон РФ',
        r'(?:\+7|8)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}',
        'Средний',
        lambda m: f'Телефон: {m[:4]}*****{m[-2:]}',
    ),
    (
        'Дата рождения',
        r'(?i)(?:дата?\s+рождени[яе]|д\.р\.|DOB|born)\s*[:\-]?\s*\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4}',
        'Средний',
        lambda m: 'Найдена дата рождения',
    ),
    (
        'Email (личный)',
        r'[a-zA-Z0-9._%+\-]+@(?:gmail|mail|yandex|yahoo|hotmail|outlook|bk|inbox|list|rambler|icloud|proton|protonmail|tutanota|ukr|internet|lenta|ro|tut|gmx|aol|msn|live)\.[a-zA-Z]{2,6}',
        'Средний',
        lambda m: f'Email: {m[:3]}***@{m.split("@")[-1] if "@" in m else "?"}',
    ),
    (
        'Гриф секретности',
        r'(?i)(?:конфиденциально|коммерческая\s+тайна|для\s+служебного\s+пользования|дсп|секретно|совершенно\s+секретно|строго\s+конфиденциально|not\s+for\s+distribution|confidential|restricted|top\s+secret|internal\s+only)',
        'Средний',
        lambda m: f'Гриф: {m.strip()}',
    ),
    (
        'Логин / учётная запись',
        r'(?i)(?:login|логин|username|user(?:name)?|учётная\s+запись|учетная\s+запись)\s*[:=]\s*\S{3,}',
        'Средний',
        lambda m: 'Найдена учётная запись / логин',
    ),
    (
        'Номер договора',
        r'(?i)(?:договор|контракт|соглашение|акт|счёт-фактура)[\s:№]+[А-ЯA-Z\d][\d\-/А-ЯA-Z]{3,}',
        'Средний',
        lambda m: f'Документ: {m.strip()[:40]}',
    ),
    (
        'Внутренний IP-адрес',
        r'\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b',
        'Средний',
        lambda m: f'Внутренний IP: {m}',
    ),
    (
        'MAC-адрес',
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
        'Средний',
        lambda m: f'MAC-адрес: {m[:8]}:***',
    ),
    (
        'Медицинские данные',
        r'(?i)(?:диагноз|МКБ[\s\-]?\d|амбулаторн|выписка\s+из|больничн|история\s+болезни|анализ\s+крови|рецепт)',
        'Средний',
        lambda m: 'Медицинская информация',
    ),

    # ════════════════════════════════════════════════════════════════════════
    # НИЗКИЙ — для сведения / мониторинг
    # ════════════════════════════════════════════════════════════════════════

    (
        'Мессенджер / соцсеть',
        r'(?i)(?:'
        r't\.me/'                        # Telegram ссылка
        r'|telegram\.(?:org|me)\b'       # Telegram сайт
        r'|telegram\s*(?:max|x)\b'       # Telegram Max / Telegram X
        r'|whatsapp\.com\b'              # WhatsApp сайт
        r'|whatsapp\b'                   # WhatsApp упоминание
        r'|vk\.com\b'                    # ВКонтакте
        r'|ok\.ru\b'                     # Одноклассники
        r'|одноклассники\b'
        r'|instagram\.com\b'
        r'|facebook\.com\b'
        r'|tiktok\.com\b'
        r'|discord\.(?:com|gg)\b'        # Discord
        r'|linkedin\.com\b'              # LinkedIn
        r'|skype\.com\b'                 # Skype
        r'|\bskype\b'
        r'|teams\.microsoft\.com\b'      # MS Teams
        r'|zoom\.us\b'                   # Zoom
        r'|slack\.com\b'                 # Slack
        r'|signal\.org\b'                # Signal
        r'|viber\.com\b'                 # Viber
        r'|\bviber\b'
        r'|wechat\.com\b'                # WeChat
        r'|web\.telegram\.org\b'         # Telegram Web
        r')',
        'Низкий',
        lambda m: f'Мессенджер/соцсеть: {m.strip()}',
    ),
    (
        'Облачное хранилище',
        r'(?i)(?:'
        r'drive\.google\.com'            # Google Drive
        r'|docs\.google\.com'            # Google Docs
        r'|dropbox\.com'                 # Dropbox
        r'|onedrive\.live\.com'          # OneDrive
        r'|sharepoint\.com'              # SharePoint
        r'|disk\.yandex\.'               # disk.yandex.ru / .com
        r'|yandex\.disk'
        r'|яндекс.{0,6}диск'             # Яндекс[любой мусор OCR]Диск
        r'|yandex.{0,6}disk'             # на случай латиницы от OCR
        r'|\bядиск\b'                    # краткое упоминание
        r'|cloud\.mail\.ru'              # Mail.ru Cloud
        r'|облако\.mail\.ru'
        r'|мое\s+облако'                 # «Моё облако» Mail.ru
        r'|mega\.nz'                     # Mega
        r'|box\.com'                     # Box
        r'|icloud\.com'                  # iCloud
        r'|wetransfer\.com'              # WeTransfer
        r'|files\.fm'                    # Files.fm
        r'|sync\.com'                    # Sync.com
        r')',
        'Низкий',
        lambda m: f'Облачное хранилище: {m.strip()}',
    ),
    (
        'Внешний носитель',
        r'(?i)(?:usb|флешка|съёмный\s+диск|removable|disk[1-9]|volume[1-9]|\bsdcard\b|\bmicrosd\b)',
        'Низкий',
        lambda m: 'Признаки подключённого внешнего носителя',
    ),
]


def _find_tesseract() -> str:
    found = shutil.which('tesseract')
    if found:
        return found
    candidates = (
        '/opt/homebrew/bin/tesseract',
        '/usr/local/bin/tesseract',
        '/usr/bin/tesseract',
        r'C:\Program Files\Tesseract-OCR\tesseract.exe',
        r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
    )
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError('Tesseract не найден')


def _run_ocr(img_path: str, lang: str) -> str:
    """Run tesseract as subprocess with hard timeout and guaranteed kill."""
    tess = _find_tesseract()
    with tempfile.NamedTemporaryFile(suffix='', delete=False, dir=tempfile.gettempdir(), prefix='dlp_') as tf:
        out_base = tf.name
    out_txt = out_base + '.txt'
    proc = None
    try:
        proc = subprocess.Popen(
            [tess, img_path, out_base, '-l', lang, '--psm', '6'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.wait(timeout=OCR_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError(f'Таймаут OCR ({OCR_TIMEOUT}с)')
        if proc.returncode != 0:
            raise RuntimeError(f'Tesseract вернул код {proc.returncode}')
        if os.path.exists(out_txt):
            with open(out_txt, encoding='utf-8', errors='replace') as f:
                return f.read()
        return ''
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
        for p in (out_base, out_txt):
            try:
                os.unlink(p)
            except OSError:
                pass


def _extract_employee(filename: str) -> tuple[str, str]:
    stem = Path(filename).stem
    parts = re.split(r'[_\-]', stem)
    for part in parts:
        if part.isalpha() and 3 <= len(part) <= 30:
            return part.capitalize(), '—'
    return 'Неизвестно', '—'


def analyze_file(filepath: str, lang: str = 'rus+eng') -> dict:
    filename = os.path.basename(filepath)
    tmp_png = None
    try:
        img_rgb_path = filepath
        ext = filepath.lower().rsplit('.', 1)[-1]
        if ext not in ('jpg', 'jpeg', 'png', 'tiff', 'tif', 'bmp'):
            with Image.open(filepath) as im:
                with tempfile.NamedTemporaryFile(suffix='.png', delete=False, dir='/tmp', prefix='dlp_img_') as tf:
                    tmp_png = tf.name
                im.convert('RGB').save(tmp_png, 'PNG')
            img_rgb_path = tmp_png

        text = _run_ocr(img_rgb_path, lang)

    except Exception as e:
        return {
            'filename': filename,
            'path': filepath,
            'ocr_text': '',
            'incidents': [],
            'error': str(e),
        }
    finally:
        if tmp_png:
            try:
                os.unlink(tmp_png)
            except OSError:
                pass

    employee, dept = _extract_employee(filename)
    incidents = []

    for vtype, pattern, severity, describe in PATTERNS:
        matches = re.findall(pattern, text)
        if not matches:
            continue
        raw = matches[0]
        if isinstance(raw, tuple):
            raw = raw[0]
        try:
            detail = describe(str(raw))
        except Exception:
            detail = f'Найдено совпадений: {len(matches)}'
        incidents.append({
            'employee': employee,
            'department': dept,
            'violation_type': vtype,
            'severity': severity,
            'detail': detail,
        })

    return {
        'filename': filename,
        'path': filepath,
        'ocr_text': text[:3000],
        'incidents': incidents,
        'error': None,
    }


def list_jpeg_files(folder: str) -> list[str]:
    result = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.lower().endswith(('.jpg', '.jpeg', '.png')):
                result.append(os.path.join(root, f))
    result.sort()
    return result
