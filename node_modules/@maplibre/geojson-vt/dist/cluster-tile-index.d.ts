import KDBush from 'kdbush';
import type { ClusterOrPointFeature, GeoJSONVTTileIndex, GeoJSONVTInternalFeature, GeoJSONVTInternalPointFeature, GeoJSONVTOptions, GeoJSONVTTile, SuperclusterOptions } from './definitions';
/** @internal */
export type KDBushWithData = KDBush & {
    /**
     * The projected x and y of each point or cluster, as integers, see `encode`.
     */
    flatCoords: Int32Array;
    /**
     * The other values of each point or cluster, at the `OFFSET_` positions.
     */
    flatData: Int32Array;
};
export declare const defaultClusterOptions: Required<SuperclusterOptions>;
/**
 * This class allow clustering of geojson points.
 */
export declare class ClusterTileIndex implements GeoJSONVTTileIndex {
    options: Required<SuperclusterOptions>;
    /**
     * A tree per zoom level. A zoom level where no clusters form shares the tree of the zoom level above it.
     */
    trees: KDBushWithData[];
    stride: number;
    clusterProps: Record<string, unknown>[];
    points: GeoJSONVTInternalPointFeature[];
    private worldCoordinateHelper;
    constructor(options?: SuperclusterOptions);
    /**
     * Loads GeoJSON Point and MultiPoint features and builds the internal clustering index.
     * Each position of a MultiPoint is clustered as a point of its own, with the id and properties of its feature.
     * @param points - GeoJSON Point and MultiPoint features to cluster.
     */
    load(points: GeoJSON.Feature<GeoJSON.Point | GeoJSON.MultiPoint>[]): void;
    /**
     * @internal
     * Loads internal GeoJSONVT point features from a data source and builds the clustering index.
     * Each position of a MultiPoint feature becomes a point of its own, with the id and properties of its feature.
     * @param features - {@link GeoJSONVTInternalFeature} data source features to filter and cluster.
     */
    initialize(features: GeoJSONVTInternalFeature[]): void;
    /**
     * @internal
     * Updates the cluster data by rebuilding.
     * @param features
     */
    updateIndex(features: GeoJSONVTInternalFeature[], _affected: GeoJSONVTInternalFeature[], options: GeoJSONVTOptions): void;
    /**
     * Builds a tree per zoom level from the points. A point whose position does not fit in an integer is left out,
     * see `fitsInteger`.
     */
    private createIndex;
    /**
     * Returns clusters and/or points within a bounding box at a given zoom level.
     * @param bbox - Bounding box in `[westLng, southLat, eastLng, northLat]` order, or `[minX, minY, maxX, maxY]` in the unit square with `coordinates: 'unitSquare'`.
     * In a world that wraps, the box can reach across the antimeridian. In one that doesn't, only its part inside the world counts.
     * @param zoom - Zoom level to query.
     */
    getClusters(bbox: [number, number, number, number], zoom: number): ClusterOrPointFeature[];
    /**
     * The clusters and points in the part of a box inside a world that ends at its edges.
     */
    private getClustersInWorld;
    /**
     * The clusters and points in a box of a unit square that wraps, where the box can reach across its left or right edge.
     */
    private getClustersAcrossEdge;
    private getClustersInternal;
    /**
     * The clusters and points in a box of the internal coordinates, `[minX, minY, maxX, maxY]`.
     */
    private getClustersInRange;
    /**
     * Returns the immediate children (clusters or points) of a cluster as GeoJSON.
     * @param clusterId - The target cluster id.
     */
    getChildren(clusterId: number): ClusterOrPointFeature[];
    /**
     * Returns leaf point features under a cluster, paginated by `limit` and `offset`.
     * @param clusterId - The target cluster id.
     * @param limit - Maximum number of points to return (defaults to `10`).
     * @param offset - Number of points to skip before collecting results (defaults to `0`).
     */
    getLeaves(clusterId: number, limit?: number, offset?: number): GeoJSON.Feature<GeoJSON.Point>[];
    /**
     * Generates a vector-tile-like representation of a single tile.
     * @param z - Tile zoom.
     * @param x - Tile x coordinate.
     * @param y - Tile y coordinate.
     */
    getTile(z: number, x: number, y: number): GeoJSONVTTile | null;
    /**
     * Returns the zoom level at which a cluster expands into multiple children.
     * @param clusterId - The target cluster id.
     */
    getClusterExpansionZoom(clusterId: number): number;
    private appendLeaves;
    private createTree;
    /**
     * Whether clustering a tree left all its points and clusters as they were, in the same order.
     */
    private isSameAsTree;
    private addTileFeatures;
    private limitZoom;
    /**
     * Clusters the points of a tree on a zoom level, writing the result to `nextCoords` and `nextData`.
     * @returns the number of points and clusters written
     */
    private cluster;
    private getOriginId;
    private getOriginZoom;
    private map;
}
//# sourceMappingURL=cluster-tile-index.d.ts.map