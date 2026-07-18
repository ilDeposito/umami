FROM node:20-alpine

RUN addgroup -S bridge && adduser -S bridge -G bridge
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js crypto.js ./

USER bridge

EXPOSE 8000
CMD ["node", "server.js"]
