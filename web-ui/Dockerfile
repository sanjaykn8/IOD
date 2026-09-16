# See rust-core/Dockerfile's note: not built/tested in this session
# (no Docker daemon available in the development sandbox).
FROM node:20-bookworm-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ARG VITE_API_BASE=http://127.0.0.1:4000/api
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
