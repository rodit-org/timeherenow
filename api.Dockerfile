FROM node:20-alpine

# Install tini for Alpine
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod +x /tini

WORKDIR /app

# Copy package file first (exclude lock to ensure fresh resolution from registry)
COPY package.json ./

# Install dependencies with extra error handling
RUN npm install --production \
    && npm cache clean --force \
    && rm -rf /root/.npm/_cacache

# Copy application files
COPY . .

# Create non-root user for better security (Alpine syntax)
RUN adduser -D -H -s /sbin/nologin nodeuser && \
    chown -R nodeuser:nodeuser /app

USER nodeuser

EXPOSE 8080

ENTRYPOINT ["/tini", "--"]

# Fix the path to point to src/app.js
CMD ["node", "src/app.js"]