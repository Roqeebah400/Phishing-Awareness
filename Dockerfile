FROM php:8.2-apache

RUN docker-php-ext-install pdo pdo_mysql mysqli
RUN apt-get update && apt-get install -y unzip curl libcurl4-openssl-dev \
    && docker-php-ext-install curl

COPY . /var/www/html/
WORKDIR /var/www/html

# Composer + PHPMailer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

RUN a2enmod rewrite
EXPOSE 80