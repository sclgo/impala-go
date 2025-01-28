-- Based on hive work: https://gist.github.com/jlovick/8b28ee5653e5f8de811d8ced42d3cb1a
-- Uses ESRI GIS tools for hadoop: https://github.com/Esri/gis-tools-for-hadoop
-- Adjust your lib location as needed.

create function default.ST_GeomFromText location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomFromText';

-- create function default.ST_AsBinary location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_AsBinary';
-- create function default.ST_AsGeoJSON location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_AsGeoJson';
-- create function default.ST_AsJSON location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_AsJson';

-- create function default.ST_AsShape location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_AsShape';
-- create function default.ST_AsText location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_AsText';
-- create function default.ST_GeomFromJSON location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomFromJson';
-- create function default.ST_GeomFromGeoJSON location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomFromGeoJson';
-- create function default.ST_GeomFromShape location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomFromShape';

-- create function default.ST_GeomFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomFromWKB';
-- create function default.ST_PointFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_PointFromWKB';
-- create function default.ST_LineFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_LineFromWKB';
-- create function default.ST_PolyFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_PolyFromWKB';
-- create function default.ST_MPointFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MPointFromWKB';
-- create function default.ST_MLineFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MLineFromWKB';
-- create function default.ST_MPolyFromWKB location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MPolyFromWKB';
-- create function default.ST_GeomCollection location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeomCollection';

-- create function default.ST_GeometryType location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeometryType';

-- create function default.ST_Point location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Point';
-- create function default.ST_PointZ location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_PointZ';
-- create function default.ST_LineString location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_LineString';
-- create function default.ST_Polygon location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Polygon';

-- create function default.ST_MultiPoint location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MultiPoint';
-- create function default.ST_MultiLineString location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MultiLineString';
-- create function default.ST_MultiPolygon location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MultiPolygon';

-- create function default.ST_SetSRID location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_SetSRID';

-- create function default.ST_SRID location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_SRID';
-- create function default.ST_IsEmpty location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_IsEmpty';
-- create function default.ST_IsSimple location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_IsSimple';
-- create function default.ST_Dimension location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Dimension';
-- create function default.ST_X location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_X';
-- create function default.ST_Y location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Y';
-- create function default.ST_MinX location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MinX';
-- create function default.ST_MaxX location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MaxX';
-- create function default.ST_MinY location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MinY';
-- create function default.ST_MaxY location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MaxY';
-- create function default.ST_IsClosed location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_IsClosed';
-- create function default.ST_IsRing location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_IsRing';
-- create function default.ST_Length location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Length';
-- create function default.ST_GeodesicLengthWGS84 location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeodesicLengthWGS84';
-- create function default.ST_Area location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Area';
-- create function default.ST_Is3D location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Is3D';
-- create function default.ST_Z location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Z';
-- create function default.ST_MinZ location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MinZ';
-- create function default.ST_MaxZ location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MaxZ';
-- create function default.ST_IsMeasured location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_IsMeasured';
-- create function default.ST_M location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_M';
-- create function default.ST_MinM location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MinM';
-- create function default.ST_MaxM location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_MaxM';
-- create function default.ST_CoordDim location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_CoordDim';
-- create function default.ST_NumPoints location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_NumPoints';
-- create function default.ST_PointN location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_PointN';
-- create function default.ST_StartPoint location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_StartPoint';
-- create function default.ST_EndPoint location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_EndPoint';
-- create function default.ST_ExteriorRing location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_ExteriorRing';
-- create function default.ST_NumInteriorRing location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_NumInteriorRing';
-- create function default.ST_InteriorRingN location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_InteriorRingN';
-- create function default.ST_NumGeometries location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_NumGeometries';
-- create function default.ST_GeometryN location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_GeometryN';
-- create function default.ST_Centroid location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Centroid';

-- create function default.ST_Contains location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Contains';
-- create function default.ST_Crosses location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Crosses';
-- create function default.ST_Disjoint location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Disjoint';
-- create function default.ST_EnvIntersects location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_EnvIntersects';
-- create function default.ST_Envelope location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Envelope';
-- create function default.ST_Equals location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Equals';
-- create function default.ST_Overlaps location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Overlaps';
-- create function default.ST_Intersects location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Intersects';
-- create function default.ST_Relate location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Relate';
-- create function default.ST_Touches location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Touches';
-- create function default.ST_Within location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Within';

-- create function default.ST_Distance location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Distance';
-- create function default.ST_Boundary location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Boundary';
-- create function default.ST_Buffer location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Buffer';
-- create function default.ST_ConvexHull location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_ConvexHull';
-- create function default.ST_Intersection location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Intersection';
-- create function default.ST_Union location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Union';
-- create function default.ST_Difference location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Difference';
-- create function default.ST_SymmetricDiff location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_SymmetricDiff';
-- create function default.ST_SymDifference location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_SymmetricDiff';

-- create function default.ST_Aggr_ConvexHull location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Aggr_ConvexHull';
-- create function default.ST_Aggr_Intersection location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Aggr_Intersection';
-- create function default.ST_Aggr_Union location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Aggr_Union';

-- create function default.ST_Bin location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_Bin';
-- create function default.ST_BinEnvelope location '/user/hive/warehouse/esri-gis.jar' symbol='com.esri.hadoop.hive.ST_BinEnvelope';

