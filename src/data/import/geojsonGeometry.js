/** Shared GeoJSON position and geometry validators; no rendering, I/O or globals. */

const GEOMETRY_TYPES = new Set([
  'Point',
  'MultiPoint',
  'LineString',
  'MultiLineString',
  'Polygon',
  'MultiPolygon',
  'GeometryCollection',
]);

/**
 * Create bounded position and line readers sharing one position budget.
 * @param {{maxPositions: number, fillAltitude?: boolean, limitMessage?: string}} options
 *   `fillAltitude` returns `[lon, lat, alt ?? 0]`; otherwise positions keep
 *   their original length. `limitMessage` is thrown when the budget is spent.
 * @returns {{position: Function, line: Function, count: () => number}}
 */
export function createGeoJsonPositionReader({
  maxPositions,
  fillAltitude = false,
  limitMessage = 'Invalid geographic position',
}) {
  let positions = 0;
  function position(p) {
    if (
      !Array.isArray(p) ||
      ![2, 3].includes(p.length) ||
      p.some((v) => !Number.isFinite(v)) ||
      Math.abs(p[0]) > 180 ||
      Math.abs(p[1]) > 90 ||
      (p.length === 3 && (p[2] < -12000 || p[2] > 1e9))
    )
      throw new Error('Invalid geographic position');
    if (++positions > maxPositions) throw new Error(limitMessage);
    return fillAltitude ? [p[0], p[1], p[2] ?? 0] : p.slice();
  }
  function line(points, ring = false) {
    if (!Array.isArray(points) || points.length < (ring ? 4 : 2))
      throw new Error('Invalid line');
    const normalized = points.map(position);
    if (ring && normalized[0].some((v, i) => v !== normalized.at(-1)[i]))
      throw new Error('Unclosed ring');
    return normalized;
  }
  return { position, line, count: () => positions };
}

/**
 * Validate any GeoJSON geometry (including GeometryCollection) and return a
 * copy with the original coordinate values. `null` stays `null`.
 * @param {object|null} geometry
 * @param {{position: Function, line: Function}} reader
 * @returns {object|null}
 */
export function readGeoJsonGeometry(geometry, reader, depth = 0) {
  if (geometry === null) return null;
  const type = geometry?.type;
  if (!GEOMETRY_TYPES.has(type)) throw new Error('Unsupported geometry');
  const c = geometry.coordinates;
  const list = (value, read) => {
    if (!Array.isArray(value)) throw new Error('Invalid coordinates');
    return value.map(read);
  };
  const polygon = (rings) => {
    if (!Array.isArray(rings) || !rings.length)
      throw new Error('Invalid polygon');
    return rings.map((ring) => reader.line(ring, true));
  };
  if (type === 'GeometryCollection') {
    if (depth > 0 || !Array.isArray(geometry.geometries))
      throw new Error('Invalid geometry collection');
    return {
      type,
      geometries: geometry.geometries.map((g) => {
        if (g === null) throw new Error('Unsupported geometry');
        return readGeoJsonGeometry(g, reader, depth + 1);
      }),
    };
  }
  let coordinates;
  if (type === 'Point') coordinates = reader.position(c);
  else if (type === 'MultiPoint') coordinates = list(c, reader.position);
  else if (type === 'LineString') coordinates = reader.line(c);
  else if (type === 'MultiLineString')
    coordinates = list(c, (l) => reader.line(l));
  else if (type === 'Polygon') coordinates = polygon(c);
  else coordinates = list(c, polygon);
  return { type, coordinates };
}
