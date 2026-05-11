FROM nginx:1.27-alpine

RUN apk add --no-cache bash gettext

COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY docker/nginx/templates/http.conf.template /etc/nginx/templates/http.conf.template
COPY docker/nginx/templates/https.conf.template /etc/nginx/templates/https.conf.template
COPY docker/nginx/entrypoint.sh /entrypoint.sh

CMD ["/bin/sh", "/entrypoint.sh"]
