import type { GeoJSONVTCoordinatesType } from './definitions';
/**
 * How the positions of the input relate to the world square the tiles cover, in which x and y run from 0 to 1.
 */
export interface WorldCoordinateHelper {
    projectX(x: number): number;
    projectY(y: number): number;
    unprojectX(x: number): number;
    unprojectY(y: number): number;
}
export declare const mercatorWorldCoordinateHelper: WorldCoordinateHelper;
export declare function getWorldCoordinateHelper(coordinates?: GeoJSONVTCoordinatesType): WorldCoordinateHelper;
//# sourceMappingURL=world-coordinate-helper.d.ts.map