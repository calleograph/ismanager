"""The four Passgen modes, with a Python endpoint for the trusted server mode."""
import itertools
import json
import re
import secrets
import string
from collections import Counter
from functools import lru_cache
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request

bp = Blueprint("passwords", __name__, url_prefix="/passwords")
WORDS = Path(__file__).parent / "static" / "passgen" / "words.json"
TRANSLIT = str.maketrans(dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
    "a b v g d e yo zh z i y k l m n o p r s t u f kh ts ch sh shch _ y _ e yu ya".split())))
RANDOM = secrets.SystemRandom()
SALT = "!@#$%+"
SPECIAL = "!@#$%^&*+?=_~:;,.-"
AMBIGUOUS = str.maketrans("", "", "Il1O0|")


def translit(value):
    return re.sub("[^a-z]", "", value.lower().translate(TRANSLIT))


@lru_cache(maxsize=1)
def vocabulary():
    data = json.loads(WORDS.read_text(encoding="utf-8"))
    words = {size: [] for size in (3, 4, 5)}
    for latin, russian in dict(data["dictionary"]).items():
        if len(latin) in words:
            words[len(latin)].append((latin, russian))
    stories = []
    for category in ("numbers", "nouns", "verbs", "results"):
        tokens = [(word, translit(word)) for word in data[category]]
        prefixes = Counter(latin[:3] for _, latin in tokens)
        stories.append([(word, latin[:4] if prefixes[latin[:3]] > 1 else latin[:3]) for word, latin in tokens])
    return words, stories


def length(form, key, minimum, maximum):
    try:
        value = int(form.get(key, ""))
    except (ValueError, TypeError):
        value = 0
    if not minimum <= value <= maximum:
        raise ValueError(f"Введите длину от {minimum} до {maximum}.")
    return value


def make_password(form):
    mode = form.get("mode")
    if mode == "random":
        size = length(form, "random_length", 4, 64)
        specials = "".join(dict.fromkeys(c for c in form.get("specials", "") if c in SPECIAL)) or SALT
        options = {"upper": string.ascii_uppercase, "lower": string.ascii_lowercase,
                   "digits": string.digits, "special": specials}
        groups = [chars for group, chars in options.items() if group in form]
        if "exclude" in form:
            groups = [chars.translate(AMBIGUOUS) for chars in groups]
        if not groups:
            raise ValueError("Включите хотя бы один тип символов.")
        chars = [secrets.choice(group) for group in groups]
        alphabet = "".join(groups)
        chars.extend(secrets.choice(alphabet) for _ in range(size - len(chars)))
        RANDOM.shuffle(chars)
        return {"password": "".join(chars), "words": []}
    if mode == "custom":
        words = form.get("phrase", "").split()
        if not 3 <= len(words) <= 5 or any(len(word) > 64 for word in words):
            raise ValueError("Введите от трёх до пяти слов длиной до 64 букв каждое.")
        fragments = [translit(word) for word in words]
        if min(map(len, fragments)) < 2 or len(set(fragments)) != len(words):
            raise ValueError("Используйте разные слова, хотя бы по две буквы.")
        if sum(map(len, fragments)) + 2 < 15:
            raise ValueError("Фраза должна давать пароль длиной не менее 15 знаков.")
    elif mode == "dictionary":
        size = length(form, "word_length", 12, 18)
        count = 2 if size < 16 else 3
        pools, _ = vocabulary()
        choices = [sizes for sizes in itertools.product(pools, repeat=count) if sum(sizes) <= size - 3]
        best = max(map(sum, choices))
        sizes = secrets.choice([sizes for sizes in choices if sum(sizes) == best])
        picks = {size: iter(RANDOM.sample(pools[size], n)) for size, n in Counter(sizes).items()}
        fragments, words = zip(*(next(picks[size]) for size in sizes))
    elif mode == "story":
        _, stories = vocabulary()
        words, fragments = zip(*(secrets.choice(pool) for pool in stories))
    else:
        raise ValueError("Выберите режим генерации.")
    parts = [part.capitalize() for part in fragments]
    positions = {"start": [0], "middle": range(1, len(parts)), "end": [len(parts)], "random": range(len(parts) + 1)}
    where = form.get("position", "random")
    if where not in positions:
        raise ValueError("Выберите положение вставки.")
    salt = [secrets.choice("23456789")] + [secrets.choice(SALT) for _ in range(1 + secrets.randbelow(2))]
    RANDOM.shuffle(salt)
    parts.insert(secrets.choice(positions[where]), "".join(salt))
    return {"password": "".join(parts), "words": list(words)}


@bp.get("/")
def index():
    return render_template("passwords/index.html")


@bp.post("/generate")
def generate():
    if request.content_length is None or request.content_length > 12000:
        return jsonify(error="Параметры генерации слишком велики."), 413
    try:
        results = {}
        for _ in range(100):
            item = make_password(request.form)
            results[item["password"]] = item
            if len(results) == 7:
                break
        return jsonify(results=list(results.values()))
    except ValueError as exc:
        return jsonify(error=str(exc)), 422


@bp.after_request
def prevent_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response
