FROM node:22-alpine
WORKDIR /app
RUN corepack enable pnpm
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod
COPY main.js ./
EXPOSE 3000
CMD ["node", "main.js"]
