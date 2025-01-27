 CREATE EXTERNAL TABLE `daylight_earth`(
   `geometry_id` string,
   `class` string,
   `subclass` string,
   `metadata` string,
   `original_source_tags` string,
   `names` string,
   `quadkey` string,
   `wkt` string)
 PARTITIONED BY (
   `release` varchar(5),
   `theme` string)
 STORED AS PARQUET
 LOCATION
   's3a://daylight-openstreetmap/earth'
 TBLPROPERTIES (
   'has_encrypted_data'='false',
   'parquet.compression'='GZIP');

alter table `daylight_earth` recover partitions;
