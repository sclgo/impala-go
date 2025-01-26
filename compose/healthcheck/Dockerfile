FROM alpine/curl:8.11.1
HEALTHCHECK \
    CMD curl -f http://impalad:25000 || exit 1
ENTRYPOINT []
# Lots of other options for "run indefinitely" did not respond to SIGTERM
# sleep, tail -f /dev/null, & wait etc
CMD ["sh", "-c", "trap \"exit\" TERM; while true; do sleep 1; done"]
