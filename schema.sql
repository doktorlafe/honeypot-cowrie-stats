-- Schéma archivu Cowrie honeypotu.
--
-- Část 1 (tabulky auth … ipforwardsdata) je oficiální Kippo/Cowrie schéma,
-- převzaté z cowrie/cowrie: docs/sql/sqlite3.sql (BSD-3-Clause,
-- Upi Tamminen, Michel Oosterhof). Držíme ho beze změny, aby nad naší
-- databází fungovaly standardní cowrie/kippo nástroje a grafy.
--
-- Část 2 (events, files, ingest_state) je náš přírůstek: surový kompletní
-- archiv všech eventů v plné věrnosti + evidence stavu ingestu a komprese.
--
-- Vše je idempotentní (IF NOT EXISTS), takže se schéma aplikuje při každém startu.

------------------------------------------------------------------ oficiální

CREATE TABLE IF NOT EXISTS `auth` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `timestamp` datetime NOT NULL
);

CREATE TABLE IF NOT EXISTS `clients` (
  `id` INTEGER PRIMARY KEY,
  `version` varchar(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS `input` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `realm` varchar(50) default NULL,
  `success` tinyint(1) default NULL,
  `input` text NOT NULL
);
CREATE INDEX IF NOT EXISTS input_index ON input(session, timestamp, realm);

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` INTEGER PRIMARY KEY,
  `ip` varchar(61) NOT NULL
);

CREATE TABLE IF NOT EXISTS `sessions` (
  `id` char(32) NOT NULL PRIMARY KEY,
  `starttime` datetime NOT NULL,
  `endtime` datetime default NULL,
  `sensor` int(4) NOT NULL,
  `ip` varchar(61) NOT NULL default '',
  `termsize` varchar(7) default NULL,
  `client` int(4) default NULL
);
CREATE INDEX IF NOT EXISTS sessions_index ON sessions(starttime, sensor);

CREATE TABLE IF NOT EXISTS `ttylog` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `ttylog` varchar(100) NOT NULL,
  `size` int(11) NOT NULL
);

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `timestamp` datetime NOT NULL,
  `url` text NOT NULL,
  `outfile` text default NULL,
  `shasum` varchar(64) default NULL
);
CREATE INDEX IF NOT EXISTS downloads_index ON downloads(session, timestamp);

CREATE TABLE IF NOT EXISTS `keyfingerprints` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `username` varchar(100) NOT NULL,
  `fingerprint` varchar(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS `params` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR( 32 ) NOT NULL,
  `arch` varchar(32) NOT NULL
);
CREATE INDEX IF NOT EXISTS arch_index ON params(arch);

CREATE TABLE IF NOT EXISTS `ipforwards` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL
);

CREATE TABLE IF NOT EXISTS `ipforwardsdata` (
  `id` INTEGER PRIMARY KEY,
  `session` CHAR(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `dst_ip` varchar(255) NOT NULL default '',
  `dst_port` int(5) NOT NULL,
  `data` text NOT NULL
);

--------------------------------------------------------------- náš archiv

-- Každý jednotlivý event z cowrie.json v plné věrnosti.
-- Běžná (společná) pole máme jako sloupce, zbytek polí eventu je v `data`
-- jako JSON — nic se neztrácí a přitom se data neukládají dvakrát.
CREATE TABLE IF NOT EXISTS `events` (
  `id`          INTEGER PRIMARY KEY,
  `timestamp`   TEXT,
  `eventid`     TEXT NOT NULL,
  `session`     TEXT,
  `protocol`    TEXT,
  `src_ip`      TEXT,
  `src_port`    INTEGER,
  `dst_ip`      TEXT,
  `dst_port`    INTEGER,
  `sensor`      TEXT,
  `uuid`        TEXT,
  `message`     TEXT,
  -- nejčastěji filtrovaná event-specifická pole vytažená bokem
  `username`    TEXT,
  `password`    TEXT,
  `input`       TEXT,
  `url`         TEXT,
  `shasum`      TEXT,
  `outfile`     TEXT,
  `version`     TEXT,
  `arch`        TEXT,
  `hassh`       TEXT,
  `ttylog`      TEXT,
  `size`        INTEGER,
  `duration_ms` INTEGER,
  -- zbytek polí daného eventu (kexAlgs, data, cve, …) jako JSON
  `data`        TEXT,
  -- Odkud event pochází. Záměrně ID souboru, ne jeho jméno: cowrie.json se
  -- při rotaci přejmenovává, a kdyby identita visela na jméně, těžko bychom
  -- rozlišili "tenhle soubor je pořád stejný" od "tohle je jiný soubor".
  -- Dvojice (file_id, line_no) je unikátní → ingest je idempotentní.
  `file_id`     INTEGER NOT NULL,
  `src_file`    TEXT NOT NULL,   -- jméno v době uložení (pro čitelnost dotazů)
  `line_no`     INTEGER NOT NULL,
  UNIQUE(`file_id`, `line_no`)
);

CREATE INDEX IF NOT EXISTS events_ts_idx       ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_eventid_idx  ON events(eventid);
CREATE INDEX IF NOT EXISTS events_session_idx  ON events(session);
CREATE INDEX IF NOT EXISTS events_srcip_idx    ON events(src_ip);
CREATE INDEX IF NOT EXISTS events_user_idx     ON events(username);
CREATE INDEX IF NOT EXISTS events_shasum_idx   ON events(shasum);
CREATE INDEX IF NOT EXISTS events_file_idx     ON events(file_id);

-- Stažené/nahrané soubory a tty nahrávky, deduplikované přes SHA256.
CREATE TABLE IF NOT EXISTS `files` (
  `shasum`     TEXT PRIMARY KEY,
  `size`       INTEGER,
  `path`       TEXT,
  `kind`       TEXT,          -- download | upload | ttylog
  `url`        TEXT,
  `first_seen` TEXT,
  `last_seen`  TEXT,
  `seen_count` INTEGER DEFAULT 0
);

-- Stav ingestu a komprese pro každý log soubor.
--
-- `file_id` je stabilní identita souboru — přežije přejmenování při rotaci.
-- `inode` slouží k rozpoznání rotace: když se cowrie.json přejmenuje na
-- cowrie.json.DATUM, je to pořád tentýž inode, takže se jen přepíše jméno
-- a pokračuje se tam, kde jsme skončili.
CREATE TABLE IF NOT EXISTS `ingest_state` (
  `file_id`     INTEGER PRIMARY KEY AUTOINCREMENT,
  `filename`    TEXT NOT NULL,      -- logický název (basename bez kompresní přípony)
  `size`        INTEGER,
  `mtime`       REAL,
  `inode`       INTEGER,
  `lines_done`  INTEGER DEFAULT 0,
  `bytes_done`  INTEGER DEFAULT 0,
  `completed`   INTEGER DEFAULT 0,  -- 1 = dočteno do konce
  `compressed`  INTEGER DEFAULT 0,  -- 1 = originál nahrazen .xz
  `events`      INTEGER DEFAULT 0,  -- kolik eventů jsme z něj uložili
  `updated`     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ingest_filename_idx ON ingest_state(filename);
CREATE INDEX IF NOT EXISTS ingest_inode_idx ON ingest_state(inode);

-- Jednoduchý log běhů archiveru (diagnostika, "kdy naposledy proběhl").
CREATE TABLE IF NOT EXISTS `archive_runs` (
  `id`        INTEGER PRIMARY KEY,
  `started`   TEXT,
  `finished`  TEXT,
  `mode`      TEXT,
  `files`     INTEGER,
  `events`    INTEGER,
  `note`      TEXT
);

------------------------------------------------------------------- pohledy

-- Pohledy pro Datasette a dashboard — pojmenované, ať se dobře používají.

DROP VIEW IF EXISTS v_top_ips;
CREATE VIEW v_top_ips AS
SELECT src_ip,
       COUNT(*)                          AS connections,
       COUNT(DISTINCT session)           AS sessions,
       MIN(timestamp)                    AS first_seen,
       MAX(timestamp)                    AS last_seen
FROM events
WHERE eventid = 'cowrie.session.connect'
GROUP BY src_ip
ORDER BY connections DESC;

DROP VIEW IF EXISTS v_top_credentials;
CREATE VIEW v_top_credentials AS
SELECT username, password,
       COUNT(*)                                                       AS attempts,
       SUM(CASE WHEN eventid = 'cowrie.login.success' THEN 1 ELSE 0 END) AS success,
       COUNT(DISTINCT src_ip)                                         AS distinct_ips,
       MIN(timestamp)                                                 AS first_seen,
       MAX(timestamp)                                                 AS last_seen
FROM events
WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')
GROUP BY username, password
ORDER BY attempts DESC;

DROP VIEW IF EXISTS v_top_commands;
CREATE VIEW v_top_commands AS
SELECT input AS command,
       COUNT(*)              AS times_seen,
       COUNT(DISTINCT session) AS sessions,
       COUNT(DISTINCT src_ip)  AS distinct_ips,
       MIN(timestamp)        AS first_seen,
       MAX(timestamp)        AS last_seen
FROM events
WHERE eventid IN ('cowrie.command.input', 'cowrie.command.success', 'cowrie.command.failed')
  AND input IS NOT NULL AND input != ''
GROUP BY input
ORDER BY times_seen DESC;

DROP VIEW IF EXISTS v_daily;
CREATE VIEW v_daily AS
SELECT substr(timestamp, 1, 10) AS day,
       COUNT(*)                                                          AS events,
       SUM(CASE WHEN eventid = 'cowrie.session.connect'      THEN 1 ELSE 0 END) AS connections,
       SUM(CASE WHEN eventid = 'cowrie.login.success'        THEN 1 ELSE 0 END) AS login_success,
       SUM(CASE WHEN eventid = 'cowrie.login.failed'         THEN 1 ELSE 0 END) AS login_failed,
       SUM(CASE WHEN eventid LIKE 'cowrie.command.%'         THEN 1 ELSE 0 END) AS commands,
       SUM(CASE WHEN eventid = 'cowrie.session.file_download' THEN 1 ELSE 0 END) AS downloads,
       COUNT(DISTINCT src_ip)                                            AS distinct_ips
FROM events
WHERE timestamp IS NOT NULL
GROUP BY day
ORDER BY day;

DROP VIEW IF EXISTS v_hourly;
CREATE VIEW v_hourly AS
SELECT substr(timestamp, 1, 13) AS hour,
       COUNT(*)                                                          AS events,
       SUM(CASE WHEN eventid = 'cowrie.session.connect' THEN 1 ELSE 0 END) AS connections,
       COUNT(DISTINCT src_ip)                                            AS distinct_ips
FROM events
WHERE timestamp IS NOT NULL
GROUP BY hour
ORDER BY hour;

-- Podle čeho útočníci poznají, že jde o stroj — verze SSH banneru a HASSH.
DROP VIEW IF EXISTS v_client_versions;
CREATE VIEW v_client_versions AS
SELECT version,
       COUNT(*)        AS times_seen,
       COUNT(DISTINCT src_ip) AS distinct_ips
FROM events
WHERE eventid = 'cowrie.client.version' AND version IS NOT NULL
GROUP BY version
ORDER BY times_seen DESC;

DROP VIEW IF EXISTS v_hassh;
CREATE VIEW v_hassh AS
SELECT hassh,
       COUNT(*)               AS times_seen,
       COUNT(DISTINCT src_ip) AS distinct_ips
FROM events
WHERE eventid = 'cowrie.client.kex' AND hassh IS NOT NULL
GROUP BY hassh
ORDER BY times_seen DESC;

-- Kolik toho každá session stihla — rychlý přehled "co útočník dělal".
DROP VIEW IF EXISTS v_session_summary;
CREATE VIEW v_session_summary AS
SELECT e.session,
       MIN(e.timestamp)                                          AS started,
       MAX(e.timestamp)                                          AS ended,
       MIN(e.src_ip)                                             AS src_ip,
       MIN(e.protocol)                                           AS protocol,
       SUM(CASE WHEN e.eventid LIKE 'cowrie.login.%'    THEN 1 ELSE 0 END) AS login_attempts,
       SUM(CASE WHEN e.eventid LIKE 'cowrie.command.%'  THEN 1 ELSE 0 END) AS commands,
       SUM(CASE WHEN e.eventid = 'cowrie.session.file_download' THEN 1 ELSE 0 END) AS downloads
FROM events e
WHERE e.session IS NOT NULL
GROUP BY e.session
ORDER BY started DESC;

-- Kdy naposledy archiv proběhl a co zpracoval.
DROP VIEW IF EXISTS v_archive_status;
CREATE VIEW v_archive_status AS
SELECT file_id, filename, lines_done, events, completed, compressed, updated
FROM ingest_state
ORDER BY filename;

-- Eventy obohacené o aktuální jméno log souboru (to se při rotaci mění).
DROP VIEW IF EXISTS v_events;
CREATE VIEW v_events AS
SELECT e.*, s.filename AS log_file
FROM events e
LEFT JOIN ingest_state s ON s.file_id = e.file_id;
