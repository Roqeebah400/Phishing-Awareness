FROM php:8.2-apache

COPY . /var/www/html/

# Install mysqli, pdo, and pdo_mysql
RUN docker-php-ext-install mysqli pdo pdo_mysql

RUN a2enmod rewrite

EXPOSE 80
