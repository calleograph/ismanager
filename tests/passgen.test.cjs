// node --test tests/passgen.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;
const generator = require('../app/static/passgen/generator.js');
const data = require('../app/static/passgen/words.json');
generator.setDictionary(data.dictionary.map(([latin]) => latin));
generator.setDictionaryRussian(data.dictionary);
generator.setStoryData(data);

test('Web Crypto generator keeps complete words, distinct story prefixes and required character groups', () => {
  for (const mode of ['custom', 'dictionary', 'story', 'random']) {
    for (let i = 0; i < 40; i++) {
      if (mode === 'random') {
        const value = generator.generateRandomPassword({length: 20, useUpper: true, useLower: true,
          useDigits: true, useSpecial: true, specialChars: '+-', excludeAmbiguous: true});
        assert.equal(value.length, 20);
        for (const rule of [/[A-Z]/, /[a-z]/, /[2-9]/, /[+-]/]) assert.match(value,rule);
        assert.doesNotMatch(value, /[Il1O0|]/);
      } else {
        const options = {source: mode, length: (i%2 ? 18 : 12), customWords: ['парус','маячок','волна'], insertPosition: 'start'};
        const item = mode === 'story' ? generator.buildStoryPassword(options) : generator.buildConstructedPassword(options);
        assert.match(item.breakdown.insert, /[2-9]/);
        assert.ok(item.password.startsWith(item.breakdown.insert));
        if (mode === 'dictionary') {
          assert.ok(item.password.length <= options.length);
          assert.equal(item.breakdown.words.length, options.length === 18 ? 3 : 2);
        } else if (mode === 'custom') assert.ok(item.password.endsWith('ParusMayachokVolna'));
        else assert.equal(item.breakdown.fragments.length, 4);
      }
    }
  }
  assert.throws(() => generator.buildConstructedPassword({source: 'custom', customWords: ['парус','парус','маяк']}));
});
