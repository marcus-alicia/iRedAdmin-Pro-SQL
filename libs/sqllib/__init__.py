# Author: Zhang Huangbin <zhb@iredmail.org>

import web
import settings

from libs.logger import logger


class MYSQLWrap:
    def __del__(self):
        try:
            self.conn.ctx.db.close()
        except Exception:
            pass

    def connect(self):
        conn = web.database(
            dbn='mysql',
            host=settings.vmail_db_host,
            port=int(settings.vmail_db_port),
            db=settings.vmail_db_name,
            user=settings.vmail_db_user,
            pw=settings.vmail_db_password,
            charset='utf8')

        conn.supports_multiple_insert = True

        return conn

    def __init__(self):
        try:
            self.conn = self.connect()
        except AttributeError:
            # Reconnect if error raised: MySQL server has gone away.
            self.conn = self.connect()
        except Exception as e:
            logger.error(e)


class PGSQLWrap:
    def __del__(self):
        try:
            self.conn.ctx.db.close()
        except Exception:
            pass

    def __init__(self):
        # Initial DB connection and cursor.
        try:
            self.conn = web.database(
                dbn='postgres',
                host=settings.vmail_db_host,
                port=int(settings.vmail_db_port),
                db=settings.vmail_db_name,
                user=settings.vmail_db_user,
                pw=settings.vmail_db_password,
            )
            self.conn.supports_multiple_insert = True
        except Exception as e:
            logger.error(e)


if settings.backend == 'mysql':
    SQLWrap = MYSQLWrap
elif settings.backend == 'pgsql':
    SQLWrap = PGSQLWrap
