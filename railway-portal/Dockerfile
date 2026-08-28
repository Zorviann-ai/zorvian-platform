FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY CAELOMERE-PORTAL-LITE.zip /tmp/caelomere.zip
RUN unzip -q /tmp/caelomere.zip -d /app && rm /tmp/caelomere.zip
RUN npm ci
RUN npm run build
ENV NODE_ENV=production
EXPOSE 8080
CMD ["sh","-c","npm run db:migrate && node .output/server/index.mjs"]
