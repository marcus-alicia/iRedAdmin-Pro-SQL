-- mailing list subscription/unsubscription confirms.
CREATE TABLE newsletter_subunsub_confirms (
    id SERIAL PRIMARY KEY,
    -- email of mailing list
    mail VARCHAR(255) NOT NULL DEFAULT '',
    -- unique server wide id
    mlid VARCHAR(255) NOT NULL DEFAULT '',
    -- email of subscriber
    subscriber VARCHAR(255) NOT NULL DEFAULT '',
    -- kinds of 'subscribe', 'unsubscribe'
    kind VARCHAR(20) NOT NULL DEFAULT '',
    -- unique server-wide id as confirm token
    token VARCHAR(255) NOT NULL DEFAULT '',
    expired INT DEFAULT 0
);
CREATE UNIQUE INDEX idx_subunsub_confirms_1 ON newsletter_subunsub_confirms (mlid, subscriber, kind);
CREATE INDEX idx_subunsub_confirms_2 ON newsletter_subunsub_confirms (mail);
CREATE INDEX idx_subunsub_confirms_3 ON newsletter_subunsub_confirms (token);
CREATE INDEX idx_subunsub_confirms_4 ON newsletter_subunsub_confirms (expired);
