'use strict';

/**
 * Ядро генератора. Пароли создаются только на клиенте, а случайные значения
 * берутся только из Web Crypto API. Math.random() намеренно не используется.
 */
const Generator = (() => {
  // Соль — удобные для набора на любой клавиатуре символы плюс обязательная
  // цифра. Многие формы проверки сложности пароля требуют цифру отдельно от
  // спецсимволов, поэтому вставка всегда содержит хотя бы одну (2–9: без 0 и 1,
  // которые легко спутать с буквами O и I/l).
  const SALT_CHARS = '!@#$%+';
  const SALT_DIGITS = '23456789';
  const SALT_MIN_LENGTH = 2;
  const SALT_MAX_LENGTH = 3;
  const AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0', '|']);

  let dictionary = [];
  let wordsByLength = new Map();

  function secureRandomInt(maxExclusive) {
    if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
      throw new Error('maxExclusive must be a positive integer');
    }
    const values = new Uint32Array(1);
    const range = 0x100000000;
    const limit = Math.floor(range / maxExclusive) * maxExclusive;
    let value;
    do {
      crypto.getRandomValues(values);
      value = values[0];
    } while (value >= limit);
    return value % maxExclusive;
  }

  function secureRandomFrom(sequence) {
    if (!sequence || sequence.length === 0) throw new Error('Нельзя выбрать символ из пустого набора');
    return sequence[secureRandomInt(sequence.length)];
  }

  function secureShuffle(items) {
    const result = items.slice();
    for (let i = result.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
  }

  function normalizeWord(word) {
    return String(word || '').toLowerCase().replace(/[^a-z]/g, '');
  }

  function setDictionary(words) {
    dictionary = Array.from(new Set((words || []).map(normalizeWord).filter(word => word.length >= 3 && word.length <= 5)));
    wordsByLength = new Map();
    dictionary.forEach(word => {
      if (!wordsByLength.has(word.length)) wordsByLength.set(word.length, []);
      wordsByLength.get(word.length).push(word);
    });
  }

  function getDictionarySize() {
    return dictionary.length;
  }

  let russianByTranslit = new Map();

  /**
   * Русские оригиналы слов словаря — только для отображения в подсказке
   * "как собран пароль". В сам пароль по-прежнему идёт транслит.
   */
  function setDictionaryRussian(pairs) {
    russianByTranslit = new Map();
    (pairs || []).forEach(([translitWord, russianWord]) => {
      russianByTranslit.set(normalizeWord(translitWord), russianWord);
    });
  }

  function russianWordFor(translitWord) {
    return russianByTranslit.get(translitWord) || translitWord;
  }

  function normalizeSpecialChars(value) {
    const chars = Array.from(new Set(String(value || '').split('')))
      .filter(char => /[!@#$%^&*+?=_~:;,\.\-]/.test(char));
    return chars.length ? chars.join('') : SALT_CHARS;
  }

  function buildCharset(options) {
    const groups = [];
    if (options.useUpper) groups.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (options.useLower) groups.push('abcdefghijklmnopqrstuvwxyz');
    if (options.useDigits) groups.push('0123456789');
    if (options.useSpecial) groups.push(normalizeSpecialChars(options.specialChars));

    const cleanGroups = groups.map(group => options.excludeAmbiguous
      ? group.split('').filter(char => !AMBIGUOUS.has(char)).join('')
      : group
    ).filter(Boolean);

    return cleanGroups.join('');
  }

  function getEnabledGroups(options) {
    const groups = [];
    if (options.useUpper) groups.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (options.useLower) groups.push('abcdefghijklmnopqrstuvwxyz');
    if (options.useDigits) groups.push('0123456789');
    if (options.useSpecial) groups.push(normalizeSpecialChars(options.specialChars));
    return groups.map(group => options.excludeAmbiguous
      ? group.split('').filter(char => !AMBIGUOUS.has(char)).join('')
      : group
    ).filter(Boolean);
  }

  function generateRandomPassword(options) {
    const groups = getEnabledGroups(options);
    const pool = groups.join('');
    const length = Number(options.length);
    if (!pool) throw new Error('Включите хотя бы один тип символов');
    if (length < groups.length) throw new Error(`Для выбранного состава нужна длина от ${groups.length}`);

    const chars = groups.map(group => secureRandomFrom(group));
    while (chars.length < length) chars.push(secureRandomFrom(pool));
    return secureShuffle(chars).join('');
  }

  function generateRandomBatch(options, count) {
    return Array.from({ length: count }, () => generateRandomPassword(options));
  }

  function buildRandomInsert() {
    const length = SALT_MIN_LENGTH + secureRandomInt(SALT_MAX_LENGTH - SALT_MIN_LENGTH + 1);
    const chars = [secureRandomFrom(SALT_DIGITS)];
    for (let i = 1; i < length; i++) chars.push(secureRandomFrom(SALT_CHARS));
    return secureShuffle(chars).join('');
  }

  function capitalize(word) {
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
  }

  function structuresFor(position, wordCount = 3) {
    const allPositions = Array.from({ length: wordCount + 1 }, (_, index) => index);
    let positions = allPositions;
    if (position === 'start') positions = [0];
    if (position === 'end') positions = [wordCount];
    if (position === 'middle') positions = allPositions.slice(1, -1);
    return positions.map(insertIndex => {
      const blocks = Array(wordCount).fill('W');
      blocks.splice(insertIndex, 0, 'I');
      return blocks.join('');
    });
  }

  function lengthCombinations(total, wordCount) {
    const available = Array.from(wordsByLength.keys()).filter(length => length >= 3 && length <= 5);
    const combinations = [];

    function build(current, remaining) {
      if (current.length === wordCount) {
        if (remaining !== 0) return;
        const needed = new Map();
        current.forEach(length => needed.set(length, (needed.get(length) || 0) + 1));
        const enoughWords = Array.from(needed).every(([length, count]) => wordsByLength.get(length).length >= count);
        if (enoughWords) combinations.push(current.slice());
        return;
      }
      available.forEach(length => {
        if (remaining - length >= 0) build([...current, length], remaining - length);
      });
    }

    build([], total);
    return combinations;
  }

  /**
   * Подбирает полные слова. Слова идут без разделителя, поэтому бюджет длины
   * учитывает только саму соль (2–3 знака). Для 12–15 знаков используются
   * два слова — три слова по три буквы каждое вместе с вставкой начинаются
   * от 16 знаков. Начиная с 16 используются три.
   */
  function pickWholeWords(targetLength) {
    if (dictionary.length < 3) throw new Error('Словарь ещё не готов');
    const preferredWordCounts = targetLength >= 16 ? [3, 2] : [2];
    const insertBudget = SALT_MAX_LENGTH;

    for (const wordCount of preferredWordCounts) {
      const maximumWordsLength = targetLength - insertBudget;
      const minimumWordsLength = wordCount * 3;
      for (let total = maximumWordsLength; total >= minimumWordsLength; total--) {
        const combinations = lengthCombinations(total, wordCount);
        if (!combinations.length) continue;

        for (let attempt = 0; attempt < 20; attempt++) {
          const lengths = secureRandomFrom(combinations);
          const chosen = [];
          let valid = true;
          lengths.forEach(length => {
            const pool = wordsByLength.get(length).filter(word => !chosen.includes(word));
            if (!pool.length) valid = false;
            else chosen.push(secureRandomFrom(pool));
          });
          if (valid) return chosen;
        }
      }
    }

    throw new Error('Для этой длины не нашлось целых слов');
  }

  const TRANSLIT = {
    а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'yo', ж: 'zh', з: 'z',
    и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r',
    с: 's', т: 't', у: 'u', ф: 'f', х: 'kh', ц: 'ts', ч: 'ch', ш: 'sh',
    щ: 'shch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya'
  };

  function transliterate(value) {
    return String(value || '')
      .trim()
      .toLowerCase()
      .split('')
      .map(char => TRANSLIT[char] !== undefined ? TRANSLIT[char] : char)
      .join('')
      .replace(/[^a-z]/g, '');
  }

  let storyData = null;

  /**
   * Строит короткие транслит-фрагменты для списка русских слов: минимум
   * 3 буквы, 4 — только если 3 не хватает для уникальности внутри списка.
   * Слово короче 3 букв в транслите используется целиком.
   */
  function buildShortForms(words) {
    const translits = words.map(transliterate);
    const shorts = translits.map(t => t.slice(0, 3));
    const seen = new Map();
    shorts.forEach((short, index) => {
      if (!seen.has(short)) seen.set(short, []);
      seen.get(short).push(index);
    });
    seen.forEach(indexes => {
      if (indexes.length > 1) {
        indexes.forEach(index => {
          shorts[index] = translits[index].slice(0, 4);
        });
      }
    });
    return shorts;
  }

  function setStoryData(data) {
    const categories = ['numbers', 'nouns', 'verbs', 'results'];
    storyData = {};
    categories.forEach(key => {
      const words = data[key] || [];
      storyData[key] = { words, shorts: buildShortForms(words) };
    });
  }

  function storyReady() {
    return !!storyData && ['numbers', 'nouns', 'verbs', 'results'].every(key => storyData[key].words.length > 0);
  }

  /**
   * Пароль-история: число + существительное + действие + итог. В самом
   * пароле каждая часть сокращена до 3–4 транслит-букв (минимум для
   * уникальности в своей категории) и слеплена без разделителя, плюс соль
   * 2–3 знака. Подсказка при этом показывает исходные русские слова
   * целиком — историю нужно читать по-русски, а не по обрезкам латиницы.
   */
  function buildStoryPassword(options) {
    if (!storyReady()) throw new Error('Словарь историй ещё не готов');
    const categories = ['numbers', 'nouns', 'verbs', 'results'];
    const picks = categories.map(key => {
      const index = secureRandomInt(storyData[key].words.length);
      return { word: storyData[key].words[index], short: storyData[key].shorts[index] };
    });

    const fragments = picks.map(pick => capitalize(pick.short));
    const insert = buildRandomInsert();
    const structure = secureRandomFrom(structuresFor(options.insertPosition, 4));

    let wordIndex = 0;
    const blocks = structure.split('').map(symbol => symbol === 'I' ? insert : fragments[wordIndex++]);
    const password = blocks.join('');

    return {
      password,
      breakdown: {
        words: picks.map(pick => pick.word),
        wordsRu: picks.map(pick => pick.word),
        fragments,
        insert,
        structure,
        source: 'story',
        wholeWords: false
      }
    };
  }

  function generateStoryBatch(options, count) {
    const results = [];
    const seen = new Set();
    let attempts = 0;
    while (results.length < count && attempts < count * 40) {
      attempts++;
      const item = buildStoryPassword(options);
      if (!seen.has(item.password)) {
        seen.add(item.password);
        results.push(item);
      }
    }
    if (!results.length) throw new Error('Не удалось создать пароль-историю');
    return results;
  }

  function validateCustomWords(words) {
    const normalized = (words || []).map(transliterate);
    if (normalized.length < 3 || normalized.length > 5) {
      throw new Error('Введите от трёх до пяти слов');
    }
    if (normalized.some(word => word.length < 2)) {
      throw new Error('В каждом слове должно быть хотя бы две буквы');
    }
    if (new Set(normalized).size !== normalized.length) throw new Error('Введите разные слова');
    if (normalized.reduce((sum, word) => sum + word.length, 0) + SALT_MIN_LENGTH < 15) {
      throw new Error('Фраза должна давать пароль длиной не менее 15 знаков');
    }
    return normalized;
  }

  function buildConstructedPassword(options) {
    const source = options.source === 'custom' ? 'custom' : 'dictionary';
    const rawWords = source === 'custom'
      ? validateCustomWords(options.customWords)
      : pickWholeWords(Number(options.length));
    const words = rawWords.map(normalizeWord);
    const wordsRu = source === 'dictionary'
      ? words.map(russianWordFor)
      : (options.customWords || []).map(word => String(word || '').trim());
    const fragments = words.map(capitalize);
    const insert = buildRandomInsert();
    const structure = secureRandomFrom(structuresFor(options.insertPosition, words.length));

    let wordIndex = 0;
    const blocks = structure.split('').map(symbol => symbol === 'I' ? insert : fragments[wordIndex++]);
    const password = blocks.join('');

    return {
      password,
      breakdown: {
        words,
        wordsRu,
        fragments,
        insert,
        structure,
        source,
        wholeWords: true
      }
    };
  }

  function generateConstructedBatch(options, count) {
    const results = [];
    const seen = new Set();
    let attempts = 0;
    while (results.length < count && attempts < count * 40) {
      attempts++;
      const item = buildConstructedPassword(options);
      if (!seen.has(item.password)) {
        seen.add(item.password);
        results.push(item);
      }
    }
    if (!results.length) throw new Error('Не удалось создать пароль с этими параметрами');
    return results;
  }

  return {
    AMBIGUOUS,
    SALT_CHARS,
    SALT_DIGITS,
    SALT_MIN_LENGTH,
    SALT_MAX_LENGTH,
    secureRandomInt,
    secureShuffle,
    normalizeSpecialChars,
    buildCharset,
    generateRandomPassword,
    generateRandomBatch,
    setDictionary,
    setDictionaryRussian,
    getDictionarySize,
    setStoryData,
    storyReady,
    transliterate,
    buildConstructedPassword,
    generateConstructedBatch,
    buildStoryPassword,
    generateStoryBatch
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = Generator;
