import { type WorldCoordinateHelper } from './world-coordinate-helper';
import type { GeoJSONVTInternalFeature } from './definitions';
/**
 * Converts internal source features back to GeoJSON format.
 */
export declare function convertToGeoJSON(source: GeoJSONVTInternalFeature[], worldCoordinateHelper?: WorldCoordinateHelper): GeoJSON.GeoJSON;
/**
 * Converts a single internal feature to GeoJSON format.
 */
export declare function featureToGeoJSON(feature: GeoJSONVTInternalFeature, worldCoordinateHelper?: WorldCoordinateHelper): GeoJSON.Feature;
export declare function unprojectPoints(coords: number[] | Float64Array, worldCoordinateHelper?: WorldCoordinateHelper): GeoJSON.Position[];
//# sourceMappingURL=deconvert.d.ts.map