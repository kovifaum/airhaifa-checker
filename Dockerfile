# Use an official lightweight Node image
FROM node:20-slim

# We don't need the standalone Chromium as we are installing Chrome specifically for Puppeteer.
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true

# Install Google Chrome Stable and fonts
# Note: this installs the necessary libs to make the browser work with Puppeteer.
RUN apt-get update && apt-get install gnupg wget -y && \
  wget --quiet --output-document=- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/google-archive.gpg && \
  sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' && \
  apt-get update && \
  apt-get install google-chrome-stable -y --no-install-recommends && \
  rm -rf /var/lib/apt/lists/*

# Set the executable path to the installed Chrome
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm ci

# Bundle app source
COPY . .

# Bind to PORT 3000 unless specified
ENV PORT=3000
EXPOSE 3000

CMD [ "npm", "start" ]
