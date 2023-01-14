import asyncio
import json
import sqlite3
from asyncio.queues import QueueFull
from logging import Logger

from configurations.cyber_scans_helper_configurations import CyberScansHelperConfigurations
from exceptions.cyber_scans_exceptions import CyberScansException
from type.verdicts import Verdicts
from type.cyber_scans_status import CyberScansStatus
from dependencies.cache import TimeLimitedCache

cache_object = TimeLimitedCache(expiration_time=1800)
queue = asyncio.Queue()


def get_configurations():
    with open("config.json", "r") as config_file:
        config = json.load(config_file)

    return config


class CyberScansHelper:

    def __init__(self, logger: Logger):
        self.logger = logger
        config = get_configurations()
        helper_config = config["cyber_scans_helper"]
        self.configurations = CyberScansHelperConfigurations(helper_config["cyber_scans_db_path"],
                                                             helper_config["mocked_await_time"],
                                                             helper_config["bulk_size"], helper_config["sleep_time"])

    @staticmethod
    def store_status_in_cache(scan_id: str, status: str):
        cache_object.set(scan_id, status)

    @staticmethod
    def get_status_from_cache(key: str):
        return cache_object.get(key)

    async def get_requests_in_bulk(self) -> [(str, str)] or None:
        requests = []
        for _ in range(self.configurations.bulk_size):
            try:
                indicator, scan_id = await queue.get()
                requests.append((indicator, scan_id))
            except RuntimeError as e:
                extra_msg = f"exception is {str(e)}, exception_type is {type(e).__name__}"
                self.logger.error("a run time error occurred while trying to get request in bulk",
                                  extra={"extra": extra_msg})
                break
            except Exception as e:
                extra_msg = f"exception is {str(e)}, exception_type is {type(e).__name__}"
                self.logger.error("an unexpected error occurred while trying to get request in bulk",
                                  extra={"extra": extra_msg})
        return requests

    async def insert_tasks_to_queue(self, indicator: str, scan_id: str):
        extra_msg = f"indicator is: {indicator}, scan_id: {scan_id}"
        self.logger.info("inserting a task to queue", extra={"extra": extra_msg})
        try:
            queue.put_nowait((indicator, scan_id))
        except QueueFull:
            self.logger.error("failed to insert new tasks. queue is full", extra={"extra": extra_msg})
            raise CyberScansException("queue is full")

        await asyncio.sleep(self.configurations.sleep_time)
        asyncio.create_task(self.processor())

    async def handle_scan(self, indicator: str, scan_id: str) -> str:
        extra_msg = f"indicator is: {indicator}, scan_id: {scan_id}"
        self.logger.info("handling scan", extra={"extra": extra_msg})
        status = CyberScansStatus.Running.name
        self.update_scan_in_systems(scan_id, status)
        # mocked await time to scan indicator and return verdict
        await asyncio.sleep(self.configurations.mocked_await_time)
        if "mal" in indicator:
            verdict = Verdicts.Malicious
        else:
            verdict = Verdicts.Approved
        return verdict.name

    async def processor(self):
        extra_msg = f"bulk_size is: {self.configurations.bulk_size}"
        self.logger.info("processing requests from queue", extra={"extra": extra_msg})
        while True:
            requests = await self.get_requests_in_bulk()
            if not requests:
                break
            for request in requests:
                indicator, scan_id = request[0], request[1]
                status = CyberScansStatus.Complete.name
                try:
                    verdict = await self.handle_scan(indicator, scan_id)
                    self.update_scan_in_systems(scan_id, status, verdict)
                except Exception as e:
                    extra_msg = f"exception is {str(e)}, exception_type is {type(e).__name__}"
                    self.logger.error("an unexpected error occurred while trying to handle scan",
                                      extra={"extra": extra_msg})
                    status = CyberScansStatus.Error.name
                    self.update_scan_in_systems(scan_id, status)

    def create_connection_to_db(self):
        conn = sqlite3.connect(self.configurations.cyber_scans_db_path)
        cursor = conn.cursor()
        return conn, cursor

    def create_db(self):
        conn, cursor = self.create_connection_to_db()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cyber_scans';")
        if not cursor.fetchone():
            cursor.execute('''DROP TABLE IF EXISTS cyber_scans''')
            cursor.execute(('''
            CREATE TABLE cyber_scans(
                id INTEGER PRIMARY KEY,
                link TEXT,
                status TEXT,
                verdict TEXT)'''))
            conn.commit()
        cursor.close()
        conn.close()

    def insert_scan_to_db(self, indicator: str, status: str) -> str:
        conn, cursor = self.create_connection_to_db()
        cursor.execute('INSERT INTO cyber_scans (link, status, verdict) VALUES (?, ?, ?)', (indicator, status, Verdicts.UnKnown.name))
        scan_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        return str(scan_id)

    def update_scan_in_db(self, scan_id: str, status: str, verdict: str = None):
        conn, cursor = self.create_connection_to_db()
        cursor.execute('UPDATE cyber_scans SET status = ?, verdict = ?'
                       ' WHERE id = ?', (status, verdict, scan_id))
        conn.commit()
        cursor.close()
        conn.close()

    def update_scan_in_systems(self, scan_id: str, status: str, verdict: str = None):
        self.update_scan_in_db(scan_id, status, verdict)
        self.store_status_in_cache(scan_id, status)
