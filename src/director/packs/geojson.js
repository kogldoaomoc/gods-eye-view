import { createGeoJsonPositionReader } from '../../data/import/geojsonGeometry.js';
import { PACK_LIMITS } from './manifest.js';

/** Decode a bounded geometry-only GeoJSON collection; properties never become HTML, styles or URLs. */
export function decodePackGeoJSON(bytes) {
  const value = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes),
  );
  if (
    value?.type !== 'FeatureCollection' ||
    !Array.isArray(value.features) ||
    value.features.length > PACK_LIMITS.features
  )
    throw new Error('Expected a bounded FeatureCollection');
  const { position, line } = createGeoJsonPositionReader({
    maxPositions: PACK_LIMITS.positions,
    fillAltitude: true,
  });
  const ids = new Set();
  return value.features.map((feature) => {
    const id = feature?.id;
    if (
      feature?.type !== 'Feature' ||
      typeof id !== 'string' ||
      !id.trim() ||
      id.length > 256 ||
      ids.has(id)
    )
      throw new Error('Features require distinct string IDs');
    ids.add(id);
    const g = feature.geometry;
    let coordinates;
    if (g?.type === 'Point') coordinates = position(g.coordinates);
    else if (g?.type === 'LineString') coordinates = line(g.coordinates);
    else if (
      g?.type === 'Polygon' &&
      Array.isArray(g.coordinates) &&
      g.coordinates.length &&
      g.coordinates.length <= 128
    )
      coordinates = g.coordinates.map((ring) => line(ring, true));
    else throw new Error('Unsupported geometry');
    return { id, type: g.type, coordinates };
  });
}
