FROM node:18
WORKDIR /app
COPY frontend/package.json frontend/vite.config.ts frontend/index.html ./ 
COPY frontend/src ./src
RUN npm install
EXPOSE 3000
CMD ["npm","run","dev"]
