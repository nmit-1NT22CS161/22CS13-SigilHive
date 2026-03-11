FROM mysql:8.0.36

# Seed a realistic ShopHub schema so standard MySQL clients work without any
# custom protocol emulation.
COPY database/mysql-init/ /docker-entrypoint-initdb.d/

EXPOSE 3306
