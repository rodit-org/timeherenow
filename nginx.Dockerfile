FROM docker.io/nginx:mainline-alpine

# Update all packages including pcre2 to patch CVE-2025-58050
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache openssl && \
    rm /etc/nginx/conf.d/default.conf && \
    mkdir -p /app/certs

COPY nginx/nginx.conf /etc/nginx/nginx.conf

RUN chown -R nginx:nginx /etc/nginx/nginx.conf /var/cache/nginx /var/log/nginx /etc/nginx/conf.d /app

USER nginx
EXPOSE 8443

CMD ["nginx", "-g", "daemon off;"]
