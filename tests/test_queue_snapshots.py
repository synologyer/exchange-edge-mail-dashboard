import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from queue_snapshots import QueueSnapshots, validate_snapshot


def snapshot(when, status='ok'):
    return {'schemaVersion': 1, 'collectedAt': when.isoformat(), 'status': status,
            'queues': [{'identity': 'mx\\24', 'messageCount': 2, 'status': 'Retry',
                        'messages': [{'identity': 'mx\\24\\1', 'sender': 'a@example.com'}]}]}


class QueueSnapshotTest(unittest.TestCase):
    def test_success_stale_failure_and_pagination(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            output = root / 'Dashboard' / 'queue-snapshot.json'
            output.parent.mkdir()
            node = {'name': 'mx1', 'host': '', 'localRoot': root}
            reader = QueueSnapshots([node], None, None, None, stale=60)
            output.write_text(json.dumps(snapshot(datetime.now(timezone.utc))), encoding='utf-8')
            reader.collect(node)
            page = reader.payload(selected_queue='mx\\24')['nodes'][0]
            self.assertEqual(page['status'], 'ok')
            self.assertEqual(page['messageCount'], 2)
            self.assertEqual(len(page['queues'][0]['messages']), 1)
            output.write_text(json.dumps(snapshot(datetime.now(timezone.utc)-timedelta(minutes=5))), encoding='utf-8')
            reader.collect(node)
            self.assertEqual(reader.payload()['nodes'][0]['status'], 'stale')
            output.write_text('{broken', encoding='utf-8')
            reader.collect(node)
            self.assertEqual(reader.payload()['nodes'][0]['status'], 'error')
            output.unlink()
            reader.collect(node)
            self.assertIn('尚未找到', reader.payload()['nodes'][0]['error'])

    def test_error_snapshot_is_not_zero_mail(self):
        value = snapshot(datetime.now(timezone.utc), 'error')
        value['queues'] = []
        reader = QueueSnapshots([], None, None, None)
        self.assertEqual(validate_snapshot(json.dumps(value).encode())['status'], 'error')
        reader.state['mx'] = {'snapshot': value, 'error': '', 'fetchedAt': time.time()}
        reader.nodes = [{'name': 'mx'}]
        page = reader.payload()['nodes'][0]
        self.assertEqual(page['status'], 'error')
        self.assertIsNone(page['messageCount'])


if __name__ == '__main__':
    unittest.main()
