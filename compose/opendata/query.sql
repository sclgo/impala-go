SELECT
	geometry_id,
	`class`,
	`subclass`,
	GET_JSON_OBJECT(names, '$.local') as name,
	CAST(GET_JSON_OBJECT(`metadata`, '$.surface_area_sq_m') AS double) as area,
	ST_GEOMFROMTEXT(wkt)
from `daylight_earth`
WHERE `class` = 'park'
    AND `subclass` <> 'grass'
--  AND `release` = 'v1.58'
    AND theme = 'landuse'  
--  AND ST_CONTAINS(
--         ST_GEOMETRYFROMTEXT(
--                 'POLYGON((-93.67167390882966 44.88741416375285,-93.29662598669525 45.24265977467033,-92.84310065209863 44.96670966763787,-93.21197278797622 44.64095920238205,-93.67167390882966 44.88741416375285))'),
--         ST_GEOMETRYFROMTEXT(wkt)
--       )
LIMIT 10;
