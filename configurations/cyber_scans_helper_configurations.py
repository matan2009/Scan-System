class CyberScansHelperConfigurations:

    def __init__(self, cyber_scans_db_path: str, mocked_await_time: int, bulk_size: int, sleep_time: int):
        self.cyber_scans_db_path = cyber_scans_db_path
        self.mocked_await_time = mocked_await_time
        self.bulk_size = bulk_size
        self.sleep_time = sleep_time
