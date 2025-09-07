# NexShop E-commerce Service Dockerfile
FROM node:18-alpine

# Set environment variables
ENV NODE_ENV=production \
    NPM_CONFIG_CACHE=/tmp/.npm

# Set work directory
WORKDIR /app

# Install system dependencies for SQLite
RUN apk add --no-cache \
    sqlite \
    python3 \
    make \
    g++

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev && npm cache clean --force

# Copy application code
COPY src/ src/
COPY server.js .

# Create directory for SQLite database
RUN mkdir -p /app/data

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001 && \
    chown -R nextjs:nodejs /app

USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })" || exit 1

# Command to run the application
CMD ["node", "server.js"]