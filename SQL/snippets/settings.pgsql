CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    account VARCHAR(255) NOT NULL DEFAULT 'global',
    k VARCHAR(255) NOT NULL,
    v TEXT
);
CREATE UNIQUE INDEX idx_settings_account_k ON settings (account, k);
