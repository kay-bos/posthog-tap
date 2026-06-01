# posthog-tap — zero-dependency local PostHog ingestion sink.
FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
ENV PORT=4000
EXPOSE 4000
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/healthz || exit 1
USER node
CMD ["node", "server.js"]
