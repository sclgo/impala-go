FROM ubuntu:oracular
RUN apt-get update && apt-get install -y zip unzip curl
ADD https://github.com/Esri/gis-tools-for-hadoop/raw/c5d4942d4e/samples/lib/esri-geometry-api.jar /esri-geometry-api.jar
ADD https://github.com/Esri/gis-tools-for-hadoop/raw/c5d4942d4e/samples/lib/spatial-sdk-hadoop.jar /spatial-sdk-hadoop.jar
WORKDIR /combinedjar
RUN unzip -o /esri-geometry-api.jar && \
  unzip -o /spatial-sdk-hadoop.jar
RUN zip -r esri-gis.jar *

HEALTHCHECK \
    CMD curl -f http://impalad:25000 || exit 1

ENTRYPOINT []
# Lots of other options for "run indefinitely" did not respond to SIGTERM
# sleep, tail -f /dev/null, & wait etc
CMD ["sh", "-c", "trap \"exit\" TERM; while true; do sleep 1; done"]
