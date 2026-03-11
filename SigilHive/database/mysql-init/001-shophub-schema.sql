CREATE DATABASE IF NOT EXISTS shophub_logs;

USE shophub;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'customer',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sku VARCHAR(32) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  category VARCHAR(60) NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  inventory_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_number VARCHAR(32) NOT NULL UNIQUE,
  user_id INT NOT NULL,
  status VARCHAR(32) NOT NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS api_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  service_name VARCHAR(64) NOT NULL,
  api_key VARCHAR(128) NOT NULL,
  secret_key VARCHAR(128) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  access_level VARCHAR(32) NOT NULL,
  mfa_enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, email, password_hash, role, last_login) VALUES
  ('shophub_admin', 'admin@shophub.local', '$2b$10$HONEYTOKEN_ADMIN_HASH', 'admin', '2026-03-11 08:41:12'),
  ('warehouse_ops', 'ops@shophub.local', '$2b$10$HONEYTOKEN_OPS_HASH', 'operator', '2026-03-11 07:15:03'),
  ('alice', 'alice@customer.local', '$2b$10$HONEYTOKEN_ALICE_HASH', 'customer', '2026-03-10 19:22:41'),
  ('bob', 'bob@customer.local', '$2b$10$HONEYTOKEN_BOB_HASH', 'customer', '2026-03-10 21:11:54');

INSERT INTO products (sku, name, category, price, inventory_count) VALUES
  ('SKU-SSH-001', 'ShopHub Security Camera', 'electronics', 149.99, 42),
  ('SKU-HOME-014', 'Smart LED Strip', 'home', 24.50, 130),
  ('SKU-FASH-007', 'ShopHub Hoodie', 'fashion', 39.00, 87),
  ('SKU-DB-099', 'Mechanical Keyboard', 'electronics', 79.95, 25);

INSERT INTO orders (order_number, user_id, status, total_amount) VALUES
  ('ORD-20260311-1001', 3, 'processing', 149.99),
  ('ORD-20260311-1002', 4, 'shipped', 63.50),
  ('ORD-20260310-0998', 3, 'delivered', 79.95);

INSERT INTO api_keys (service_name, api_key, secret_key) VALUES
  ('stripe', 'pk_live_HONEYTOKEN_STRIPE_001', 'sk_live_HONEYTOKEN_STRIPE_SECRET'),
  ('sendgrid', 'SG.HONEYTOKEN_SENDGRID_007', 'SG_SECRET_HONEYTOKEN_007'),
  ('aws-backups', 'AKIA_HONEYTOKEN_AWS_001', 'wJalrXUtnHONEYTOKENAWSSECRET');

INSERT INTO admin_users (username, email, access_level, mfa_enabled) VALUES
  ('root_console', 'root-console@shophub.local', 'superadmin', 1),
  ('dbadmin', 'dbadmin@shophub.local', 'dba', 1),
  ('support_admin', 'support@shophub.local', 'support', 0);

USE shophub_logs;

CREATE TABLE IF NOT EXISTS audit_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  actor VARCHAR(128) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  event_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  details TEXT
);

INSERT INTO audit_events (event_type, actor, source_ip, details) VALUES
  ('LOGIN_SUCCESS', 'shophub_admin', '10.24.8.12', 'Admin console access from corporate VPN'),
  ('API_KEY_ROTATION', 'dbadmin', '10.24.8.18', 'Rotated stripe key for spring release'),
  ('BACKUP_RESTORE_TEST', 'warehouse_ops', '10.24.9.22', 'Validated order restore into staging');

CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED WITH mysql_native_password BY 'admin123';
GRANT SELECT, SHOW VIEW ON shophub.* TO 'admin'@'%';
GRANT SELECT ON shophub_logs.* TO 'admin'@'%';
FLUSH PRIVILEGES;
