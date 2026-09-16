# See rust-core/Dockerfile's note: not built/tested in this session
# (no Docker daemon available in the development sandbox).
FROM node:20-bookworm-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:20-bookworm-slim
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
ENV IOD_NODE_PORT=4000
ENV IOD_RUST_BASE_URL=http://rust-core:8787
ENV IOD_PYTHON_BASE_URL=http://python-rag:5001
EXPOSE 4000
CMD ["node", "dist/index.js"]
