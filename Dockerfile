FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml* pnpm-workspace.yaml ./
RUN corepack enable && pnpm install --no-frozen-lockfile
COPY tsconfig.json ./
COPY scripts ./scripts
COPY src ./src
COPY public ./public
RUN pnpm build && pnpm prune --prod

FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3
RUN addgroup -S hedgeweb && adduser -S -G hedgeweb hedgeweb
WORKDIR /app
COPY --from=build --chown=hedgeweb:hedgeweb /app/dist ./dist
COPY --from=build --chown=hedgeweb:hedgeweb /app/public ./public
COPY --from=build --chown=hedgeweb:hedgeweb /app/node_modules ./node_modules
COPY --from=build --chown=hedgeweb:hedgeweb /app/package.json ./package.json
RUN mkdir /data && chown hedgeweb:hedgeweb /data
USER hedgeweb
ENV NODE_ENV=production DATA_DIR=/data PORT=8080
EXPOSE 8080
CMD ["node", "dist/server.js"]
