SELECT
	geometry_id,
	`class`,
	`subclass`,
	GET_JSON_OBJECT(names, '$.local') as name,
	CAST(GET_JSON_OBJECT(`metadata`, '$.surface_area_sq_m') AS double) as area,
	wkt
from `daylight_earth`
WHERE `release` = 'v1.55'
  AND theme = 'landuse'
  AND `class` = 'park'
  AND `subclass` <> 'grass'
LIMIT 10;
