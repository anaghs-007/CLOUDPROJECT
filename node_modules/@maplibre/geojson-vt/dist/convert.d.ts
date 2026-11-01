import type { GeoJSONVTInternalFeature, GeoJSONVTOptions } from './definitions';
/**
 * converts GeoJSON to internal source features (an intermediate projected JSON vector format with simplification data)
 * @param data
 * @param options
 * @param unlocated - the features without coordinates, by id: a feature with an id that converts to nothing is set in it, and one that converts to something is deleted from it
 * @returns
 */
export declare function convertToInternal(data: GeoJSON.GeoJSON, options: GeoJSONVTOptions, unlocated?: Map<string | number, GeoJSON.Feature>): GeoJSONVTInternalFeature[];
//# sourceMappingURL=convert.d.ts.map