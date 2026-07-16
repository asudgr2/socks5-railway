FROM node:20-alpine

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY start.sh ./

RUN chmod 0555 /app/start.sh \
    && chown -R node:node /app

USER node
ENV NODE_ENV=production
EXPOSE 1080
CMD ["/app/start.sh"]
