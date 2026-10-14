FROM node:20-bookworm-slim

# أدوات البناء لازمة لتصريف better-sqlite3 عند غياب نسخة مبنية مسبقًا.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
# مسارا التخزين يجب أن يكونا داخل Volume دائم على الاستضافة.
ENV DATA_DIR=/data
ENV MEDIA_DIR=/media

VOLUME ["/data", "/media"]

EXPOSE 3000

CMD ["node", "server.js"]
