FROM node:20-alpine

WORKDIR /app
# Install real security tools for the dashboard to utilize
RUN apk add --no-cache nmap nmap-scripts bind-tools curl jq iproute2

COPY package*.json ./
RUN npm ci

COPY . .
# Disable telemetry during build
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
