/** Normalized, full-fidelity records for user-imported datasets. */
import {
  createGeoJsonPositionReader,
  readGeoJsonGeometry,
} from './geojsonGeometry.js';

/** Import ceilings: file bytes, features and positions per dataset. */
export const IMPORT_LIMITS = Object.freeze({
  bytes: 50 * 1024 * 1024,
  features: 200_000,
  positions: 5_000_000,
});

/** Accepted `consent.basis` values. Consent is metadata, never a gate. */
export const CONSENT_BASES = Object.freeze([
  'owned',
  'consented',
  'open-license',
]);

const MAX_NOTE_LENGTH = 2000;
const TIME_KEYS = ['time', 'timestamp', 'datetime', 'date'];

/** A user-facing import refusal; `code` is stable for callers and tests. */
export class ImportError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ImportError';
    this.code = code;
  }
}

const note = (value) =>
  typeof value === 'string' && value.trim()
    ? value.trim().slice(0, MAX_NOTE_LENGTH)
    : undefined;

/**
 * Keep a consent note only when its basis is known; anything else is dropped
 * rather than refusing the import.
 * @returns {{basis: string, note: string}|undefined}
 */
export function normalizeConsent(consent) {
  if (!consent || !CONSENT_BASES.includes(consent.basis)) return undefined;
  return { basis: consent.basis, note: note(consent.note) ?? '' };
}

/** Normalize a precision in metres, or `null` when unknown. */
export function normalizePrecision(meters) {
  return { meters: Number.isFinite(meters) && meters >= 0 ? meters : null };
}

function recordTime(props) {
  for (const key of TIME_KEYS) {
    const value = props?.[key];
    if (typeof value !== 'string' && !Number.isFinite(value)) continue;
    const ms = typeof value === 'string' ? Date.parse(value) : value;
    if (Number.isFinite(ms)) return new Date(ms).toISOString();
  }
  return undefined;
}

/**
 * Turn parsed GeoJSON into normalized records. Geometry keeps its original
 * coordinates and every property is retained as plain data; nothing here
 * produces HTML, styles or URLs.
 * @param {object} value FeatureCollection, Feature or bare geometry.
 * @param {{provenance: {file: string, sha256: string|null, importedAt: string,
 *   sourceNote?: string}, consent?: object, precisionMeters?: number|null,
 *   limits?: Partial<typeof IMPORT_LIMITS>}} options
 * @returns {Array<{id: string, geometry: object|null, time?: string,
 *   props: object, provenance: object, consent?: object,
 *   precision: {meters: number|null}}>}
 */
export function normalizeGeoJsonRecords(
  value,
  { provenance, consent, precisionMeters = null, limits = {} },
) {
  const max = { ...IMPORT_LIMITS, ...limits };
  let features;
  if (value?.type === 'FeatureCollection') {
    if (!Array.isArray(value.features))
      throw new ImportError(
        'That FeatureCollection has no features list.',
        'shape',
      );
    features = value.features;
  } else if (value?.type === 'Feature') features = [value];
  else if (value && typeof value === 'object' && typeof value.type === 'string')
    features = [{ type: 'Feature', geometry: value, properties: null }];
  else throw new ImportError('That file is not GeoJSON.', 'shape');
  if (features.length > max.features)
    throw new ImportError(
      `That file has ${features.length} features; the limit is ${max.features}.`,
      'features',
    );
  const reader = createGeoJsonPositionReader({
    maxPositions: max.positions,
    limitMessage: `Over ${max.positions} positions`,
  });
  const sharedProvenance = Object.freeze({
    file: String(provenance?.file ?? ''),
    sha256: provenance?.sha256 ?? null,
    importedAt: String(provenance?.importedAt ?? ''),
    ...(note(provenance?.sourceNote)
      ? { sourceNote: note(provenance.sourceNote) }
      : {}),
  });
  const sharedConsent = normalizeConsent(consent);
  const ids = new Set();
  return features.map((feature, index) => {
    if (feature?.type !== 'Feature')
      throw new ImportError(
        `Feature ${index + 1} is not a GeoJSON Feature.`,
        'shape',
      );
    let geometry;
    try {
      geometry = readGeoJsonGeometry(feature.geometry ?? null, reader);
    } catch (error) {
      const over = reader.count() > max.positions;
      throw new ImportError(
        over
          ? `That file has more than ${max.positions} positions.`
          : `Feature ${index + 1}: ${error.message}.`,
        over ? 'positions' : 'geometry',
      );
    }
    const raw = feature.id;
    let id =
      typeof raw === 'string' || Number.isFinite(raw)
        ? String(raw)
        : `${index}`;
    if (ids.has(id)) id = `${id}~${index}`;
    ids.add(id);
    const props =
      feature.properties && typeof feature.properties === 'object'
        ? feature.properties
        : {};
    const time = recordTime(props);
    return {
      id,
      geometry,
      ...(time ? { time } : {}),
      props,
      provenance: sharedProvenance,
      ...(sharedConsent ? { consent: sharedConsent } : {}),
      precision: normalizePrecision(precisionMeters),
    };
  });
}

/** Lowercase hex SHA-256 of the bytes, or `null` without WebCrypto (insecure origins). */
export async function sha256Hex(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decode GeoJSON bytes into one dataset and its records.
 * @param {Uint8Array} bytes
 * @param {{file: string, importedAt?: string, sourceNote?: string,
 *   consent?: object, precisionMeters?: number|null,
 *   limits?: Partial<typeof IMPORT_LIMITS>}} options
 */
export async function decodeGeoJsonImport(bytes, options) {
  const max = { ...IMPORT_LIMITS, ...options.limits };
  if (bytes.byteLength > max.bytes)
    throw new ImportError(
      `That file is larger than ${Math.round(max.bytes / 1024 / 1024)} MiB.`,
      'bytes',
    );
  let value;
  try {
    value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true })
        .decode(bytes)
        .replace(/^\uFEFF/, ''),
    );
  } catch {
    throw new ImportError('That file is not valid UTF-8 JSON.', 'json');
  }
  const importedAt = options.importedAt ?? new Date().toISOString();
  const provenance = {
    file: options.file,
    sha256: await sha256Hex(bytes),
    importedAt,
    sourceNote: options.sourceNote,
  };
  const records = normalizeGeoJsonRecords(value, { ...options, provenance });
  const first = records[0];
  const dataset = {
    id: `ds-${Date.parse(importedAt) || Date.now()}-${(provenance.sha256 ?? Math.random().toString(16).slice(2)).slice(0, 12)}`,
    name: options.file,
    format: 'geojson',
    featureCount: records.length,
    provenance: first?.provenance ?? provenance,
    ...(first?.consent ? { consent: first.consent } : {}),
    precision: normalizePrecision(options.precisionMeters),
  };
  return { dataset, records };
}

/** Rebuild a FeatureCollection from stored records (for the existing renderer). */
export function recordsToFeatureCollection(records) {
  return {
    type: 'FeatureCollection',
    features: records.map((r) => ({
      type: 'Feature',
      id: r.id,
      geometry: r.geometry,
      properties: r.props,
    })),
  };
}
