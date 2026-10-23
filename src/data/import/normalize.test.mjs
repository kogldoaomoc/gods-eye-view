import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { decodePackGeoJSON } from '../../director/packs/geojson.js';
import {
  IMPORT_LIMITS,
  ImportError,
  decodeGeoJsonImport,
  normalizeGeoJsonRecords,
  recordsToFeatureCollection,
} from './normalize.js';
import {
  createImportLibrary,
  createImportStore,
  createMemoryImportStore,
} from './store.js';

const fixture = (name) =>
  new Uint8Array(
    readFileSync(new URL(`../fixtures/import/${name}`, import.meta.url)),
  );
const opts = { file: 'f.geojson', importedAt: '2026-10-23T15:00:00.000Z' };

test('valid GeoJSON keeps full fidelity with provenance and precision', async () => {
  const bytes = fixture('valid.geojson');
  const { dataset, records } = await decodeGeoJsonImport(bytes, {
    ...opts,
    sourceNote: 'My survey',
    consent: { basis: 'owned', note: 'I collected it' },
    precisionMeters: 5,
  });
  const original = JSON.parse(new TextDecoder().decode(bytes));
  assert.equal(records.length, 4);
  assert.deepEqual(
    records.map((r) => r.id),
    ['hut-1', '1', '7', 'hut-1~3'],
  );
  assert.deepEqual(records[0].geometry, original.features[0].geometry);
  assert.deepEqual(records[0].props, original.features[0].properties);
  assert.equal(records[0].time, '2026-10-01T08:30:00.000Z');
  assert.deepEqual(records[1].props, {});
  assert.deepEqual(records[2].geometry, original.features[2].geometry);
  assert.equal(records[3].geometry, null);
  assert.match(records[0].provenance.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(
    { ...records[0].provenance, sha256: 'x' },
    {
      file: 'f.geojson',
      sha256: 'x',
      importedAt: opts.importedAt,
      sourceNote: 'My survey',
    },
  );
  assert.deepEqual(records[0].consent, {
    basis: 'owned',
    note: 'I collected it',
  });
  assert.deepEqual(records[0].precision, { meters: 5 });
  assert.equal(dataset.featureCount, 4);
  assert.equal(dataset.format, 'geojson');
});

test('consent is optional metadata, never a gate', async () => {
  const none = await decodeGeoJsonImport(fixture('valid.geojson'), opts);
  assert.equal(none.records.length, 4);
  assert.equal('consent' in none.records[0], false);
  assert.deepEqual(none.records[0].precision, { meters: null });
  const odd = await decodeGeoJsonImport(fixture('valid.geojson'), {
    ...opts,
    consent: { basis: 'unknown' },
  });
  assert.equal(odd.records.length, 4);
  assert.equal('consent' in odd.records[0], false);
});

test('an out-of-range coordinate is refused with its feature number', async () => {
  await assert.rejects(
    decodeGeoJsonImport(fixture('invalid-coordinates.geojson'), opts),
    (e) =>
      e instanceof ImportError &&
      e.code === 'geometry' &&
      /Feature 2/.test(e.message),
  );
});

test('feature, position and byte caps refuse with clear errors', async () => {
  assert.equal(IMPORT_LIMITS.features, 200_000);
  assert.equal(IMPORT_LIMITS.bytes, 50 * 1024 * 1024);
  await assert.rejects(
    decodeGeoJsonImport(fixture('over-limit.geojson'), {
      ...opts,
      limits: { features: 2 },
    }),
    { code: 'features', message: 'That file has 3 features; the limit is 2.' },
  );
  await assert.rejects(
    decodeGeoJsonImport(fixture('over-limit.geojson'), {
      ...opts,
      limits: { positions: 2 },
    }),
    { code: 'positions' },
  );
  await assert.rejects(
    decodeGeoJsonImport(fixture('over-limit.geojson'), {
      ...opts,
      limits: { bytes: 10 },
    }),
    { code: 'bytes' },
  );
  await assert.rejects(
    decodeGeoJsonImport(new TextEncoder().encode('{nope'), opts),
    {
      code: 'json',
    },
  );
});

test('HTML-like properties stay as untouched text', async () => {
  const { records } = await decodeGeoJsonImport(
    fixture('html-properties.geojson'),
    opts,
  );
  assert.equal(records[0].props.name, '<img src=x onerror=alert(1)>');
  assert.equal(
    records[0].props.description,
    "<script>alert('x')</script><b>bold</b>",
  );
  assert.equal(records[0].props.link, 'javascript:alert(1)');
  for (const value of Object.values(records[0].props))
    assert.equal(typeof value, 'string');
});

test('bare geometries and single features normalize', () => {
  const provenance = { file: 'g', sha256: null, importedAt: 't' };
  const [r] = normalizeGeoJsonRecords(
    { type: 'Point', coordinates: [1, 2] },
    { provenance },
  );
  assert.deepEqual(r.geometry, { type: 'Point', coordinates: [1, 2] });
  assert.throws(() => normalizeGeoJsonRecords({ foo: 1 }, { provenance }), {
    code: 'shape',
  });
});

test('pack decoding keeps its own limits and output after the extraction', () => {
  const encode = (value) => new TextEncoder().encode(JSON.stringify(value));
  const fc = {
    type: 'FeatureCollection',
    features: [
      {
        type: 'Feature',
        id: 'a',
        geometry: { type: 'Point', coordinates: [1, 2] },
      },
    ],
  };
  assert.deepEqual(decodePackGeoJSON(encode(fc)), [
    { id: 'a', type: 'Point', coordinates: [1, 2, 0] },
  ]);
  const line = Array.from({ length: 50_001 }, (_, i) => [0, (i % 80) / 1000]);
  fc.features[0].geometry = { type: 'LineString', coordinates: line };
  assert.throws(
    () => decodePackGeoJSON(encode(fc)),
    /Invalid geographic position/,
  );
  fc.features[0].geometry = { type: 'MultiPoint', coordinates: [[1, 2]] };
  assert.throws(() => decodePackGeoJSON(encode(fc)), /Unsupported geometry/);
});

test('the IndexedDB store does not open until first use', async () => {
  let opened = 0;
  const store = createImportStore({
    indexedDB: () => ((opened += 1), undefined),
  });
  assert.equal(opened, 0);
  await assert.rejects(store.listDatasets(), /IndexedDB is unavailable/);
  assert.equal(opened, 1);
});

test('the library keeps, restores and deletes datasets', async () => {
  const items = new Map();
  const storage = {
    getItem: (k) => items.get(k) ?? null,
    setItem: (k, v) => items.set(k, v),
    removeItem: (k) => items.delete(k),
  };
  let created = 0;
  const store = createMemoryImportStore();
  const library = createImportLibrary({
    createStore: () => ((created += 1), store),
    storage,
    decode: (bytes, o) =>
      decodeGeoJsonImport(bytes, { ...o, importedAt: opts.importedAt }),
    toFeatureCollection: recordsToFeatureCollection,
  });
  assert.equal(library.hasSaved(), false);
  assert.deepEqual(await library.restore(), []);
  assert.equal(created, 0, 'nothing saved: the store is never created');
  const bytes = fixture('html-properties.geojson');
  const file = new File([bytes], 'mine.geojson');
  const dataset = await library.save(file);
  assert.equal(library.hasSaved(), true);
  const [restored] = await library.restore();
  assert.equal(restored.name, 'mine.geojson');
  assert.equal(restored.gevDatasetId, dataset.id);
  const fc = JSON.parse(await restored.text());
  assert.equal(fc.features[0].properties.name, '<img src=x onerror=alert(1)>');
  await library.remove(dataset.id);
  assert.deepEqual(await store.listDatasets(), []);
  assert.deepEqual(await store.getRecords(dataset.id), []);
  assert.equal(library.hasSaved(), false);
});
