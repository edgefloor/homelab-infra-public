FROM oven/bun:1.4.0-slim@sha256:4c3ac64f41e0a47e28403789a63ecdca7987f322fa811bf5b3cb0f25f18443cc

WORKDIR /app
COPY --chown=bun:bun index.html server.js ./

USER bun
ENV HOST=0.0.0.0 \
    PORT=3000
EXPOSE 3000

CMD ["bun", "run", "server.js"]
