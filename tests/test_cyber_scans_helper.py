import asyncio
from unittest import TestCase, mock

from service.cyber_scans_helper import CyberScansHelper
from type.cyber_scans_status import CyberScansStatus


class TestCyberScansHelper(TestCase):

    @mock.patch("service.cyber_scans_helper.get_configurations")
    def setUp(self, mocked_config) -> None:
        mocked_config.return_value = {"cyber_scans_helper": {"mocked_await_time": 1, "cyber_scans_db_path": "path",
                                                             "bulk_size": 4, "sleep_time": 3}}
        self.helper_instance = CyberScansHelper(logger=mock.Mock())

    def test_handle_scan_approved(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.handle_scan_approved())

    async def handle_scan_approved(self):
        indicator, scan_id = "a.com", "123"
        self.helper_instance.update_scan_in_systems = mock.Mock()
        verdict = await self.helper_instance.handle_scan(indicator, scan_id)
        self.assertEqual(verdict, "Approved")
        self.helper_instance.update_scan_in_systems.assert_called_once_with(scan_id,
                                                                            CyberScansStatus.Running.name)

    def test_handle_scan_malicious(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.handle_scan_malicious())

    async def handle_scan_malicious(self):
        indicator, scan_id = "malicious.com", "123"
        self.helper_instance.update_scan_in_systems = mock.Mock()
        verdict = await self.helper_instance.handle_scan(indicator, scan_id)
        self.assertEqual(verdict, "Malicious")
        self.helper_instance.update_scan_in_systems.assert_called_once_with(scan_id,
                                                                            CyberScansStatus.Running.name)

    def test_processor_success(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.processor_success())

    async def processor_success(self):
        self.helper_instance.get_requests_in_bulk = mock.AsyncMock(side_effect=[[("indicator", "scan_id")], None])
        self.helper_instance.handle_scan = mock.AsyncMock(side_effect=["Approved"])
        self.helper_instance.update_scan_in_systems = mock.Mock()
        await self.helper_instance.processor()
        self.assertEqual(self.helper_instance.get_requests_in_bulk.await_count, 2)
        self.assertEqual(self.helper_instance.handle_scan.await_count, 1)
        self.helper_instance.update_scan_in_systems.assert_called_once_with("scan_id", CyberScansStatus.Complete.name,
                                                                            "Approved")

    def test_processor_exception(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.processor_exception())

    async def processor_exception(self):
        self.helper_instance.get_requests_in_bulk = mock.AsyncMock(side_effect=[[("indicator", "scan_id")], None])
        self.helper_instance.handle_scan = mock.AsyncMock(side_effect=[Exception])
        self.helper_instance.update_scan_in_systems = mock.Mock()
        await self.helper_instance.processor()
        self.assertEqual(self.helper_instance.get_requests_in_bulk.await_count, 2)
        self.assertEqual(self.helper_instance.handle_scan.await_count, 1)
        self.helper_instance.update_scan_in_systems.assert_called_once_with("scan_id", CyberScansStatus.Error.name)
