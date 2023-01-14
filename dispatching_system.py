from fastapi import FastAPI
import uvicorn

from monitoring.logger import create_logger
from service.cyber_scans_helper import CyberScansHelper
from type.cyber_scans_status import CyberScansStatus

app = FastAPI()


@app.post('/ingest/{indicator}')
async def ingest_scans(indicator: str) -> str or None:
    extra_msg = f"indicator is: {indicator}"
    logger.info(f"got a request to ingest scan for indicator", extra={"extra": extra_msg})
    status = CyberScansStatus.Accepted.name
    try:
        scan_id = cyber_scans_helper.insert_scan_to_db(indicator, status)
    except Exception as e:
        extra_msg = f"the indicator is: {indicator}, the exception is: {str(e)}, the exception_type is: {type(e).__name__}"
        logger.critical(f"an error occurred while trying to insert a new scan to db", extra={"extra": extra_msg})
        return

    cyber_scans_helper.store_status_in_cache(scan_id, status)
    try:
        await cyber_scans_helper.insert_tasks_to_queue(indicator, scan_id)
    except Exception as e:
        extra_msg = f"the indicator is: {indicator}, the scan_id is: {scan_id}, the exception is: {str(e)}, " \
                    f"the exception_type is: {type(e).__name__}"
        logger.error(f"an error occurred while trying to insert tasks to queue", extra={"extra": extra_msg})
        status = CyberScansStatus.Error.name
        cyber_scans_helper.update_scan_in_systems(scan_id, status)
    finally:
        return scan_id


@app.get('/status/{scan_id}')
def get_scan_status(scan_id: str) -> str:
    extra_msg = f"scan_id: {scan_id}"
    logger.info("got a request to get scan status", extra={"extra": extra_msg})
    status = cyber_scans_helper.get_status_from_cache(scan_id)
    if status:
        extra_msg += f", status is: {status}"
        logger.info("status extracted from cache", extra={"extra": extra_msg})
        return status
    else:
        conn, cursor = cyber_scans_helper.create_connection_to_db()
        scan_rec = cursor.execute('SELECT * FROM cyber_scans WHERE id = ?', (scan_id,)).fetchone()
        cursor.close()
        conn.close()
        if scan_rec:
            # scan record format is (scan_id, indicator, status, verdict)
            status = scan_rec[2]
            extra_msg += f", status is: {status}"
            logger.info("status extracted from DB", extra={"extra": extra_msg})
            return status

    logger.warning("the requested scan_id could not be found", extra={"extra": extra_msg})
    return CyberScansStatus.NotFound.name


def main():
    cyber_scans_helper.create_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == '__main__':
    logger = create_logger()
    cyber_scans_helper = CyberScansHelper(logger)
    main()
