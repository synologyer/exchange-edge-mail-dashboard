"""Read-only, bounded queue snapshots; no remote command execution."""
import json
import threading
import time
from datetime import datetime, timezone

MAX_BYTES = 8 * 1024 * 1024


def validate_snapshot(raw):
    value = json.loads(raw.decode('utf-8-sig'))
    if value.get('schemaVersion') != 1 or value.get('status') not in ('ok', 'error'):
        raise ValueError('不支持的队列快照格式')
    stamp = datetime.fromisoformat(value['collectedAt'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('采集时间必须包含时区')
    queues = value.get('queues')
    if not isinstance(queues, list) or len(queues) > 5000:
        raise ValueError('队列列表格式错误或超过限制')
    count = 0
    for queue in queues:
        if not isinstance(queue, dict) or not isinstance(queue.get('identity'), str):
            raise ValueError('队列缺少标识')
        if type(queue.get('messageCount')) is not int or queue['messageCount'] < 0:
            raise ValueError('队列数量无效')
        messages = queue.get('messages', [])
        if not isinstance(messages, list) or any(not isinstance(m, dict) for m in messages):
            raise ValueError('邮件概要格式错误')
        count += len(messages)
    if count > 2000:
        raise ValueError('邮件概要超过限制')
    return value


class QueueSnapshots:
    def __init__(self, nodes, password, verify, paramiko, interval=30, stale=120):
        self.nodes, self.password, self.verify, self.paramiko = nodes, password, verify, paramiko
        self.interval, self.stale = max(10, interval), max(60, stale)
        self.lock = threading.Lock()
        self.state = {}

    def read(self, node):
        if not node['host']:
            with (node['localRoot'] / 'Dashboard' / 'queue-snapshot.json').open('rb') as stream:
                raw = stream.read(MAX_BYTES + 1)
        else:
            if self.paramiko is None:
                raise RuntimeError('SFTP 不可用')
            # A separate connection avoids waiting for the historical log synchronizer.
            client = self.paramiko.SSHClient()
            owner = self

            class PinnedKey(self.paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    owner.verify(key, node['fingerprint'])

            client.set_missing_host_key_policy(PinnedKey())
            try:
                client.connect(node['host'], port=node['port'], username=node['user'],
                               password=self.password(node), timeout=10, banner_timeout=10,
                               auth_timeout=10, allow_agent=False, look_for_keys=False)
                with client.open_sftp() as sftp:
                    sftp.get_channel().settimeout(15)
                    with sftp.open(node['root'] + '/Dashboard/queue-snapshot.json', 'rb') as stream:
                        raw = stream.read(MAX_BYTES + 1)
            finally:
                client.close()
        if len(raw) > MAX_BYTES:
            raise ValueError('队列快照超过 8 MB 限制')
        return validate_snapshot(raw)

    def collect(self, node):
        try:
            snapshot = self.read(node)
            with self.lock:
                self.state[node['name']] = {'snapshot': snapshot, 'error': '', 'fetchedAt': time.time()}
        except FileNotFoundError:
            self.failed(node, '尚未找到队列快照，请在此 MX 安装采集任务')
        except Exception as exc:
            self.failed(node, str(exc))

    def failed(self, node, error):
        with self.lock:
            previous = self.state.get(node['name'], {})
            self.state[node['name']] = {**previous, 'error': error}

    def start(self):
        def run(node):
            while True:
                self.collect(node)
                time.sleep(self.interval)
        for node in self.nodes:
            threading.Thread(target=run, args=(node,), name='queue-' + node['name'], daemon=True).start()

    def payload(self, selected_node='', selected_queue='', page=1):
        result = []
        with self.lock:
            states = dict(self.state)
        for node in self.nodes:
            if selected_node and node['name'] != selected_node:
                continue
            state = states.get(node['name'], {})
            snapshot = state.get('snapshot')
            item = {'name': node['name'], 'status': 'unavailable', 'error': state.get('error', ''),
                    'collectedAt': None, 'messageCount': None, 'queues': []}
            if snapshot:
                age = time.time() - datetime.fromisoformat(snapshot['collectedAt'].replace('Z', '+00:00')).timestamp()
                item.update(collectedAt=snapshot['collectedAt'], error=state.get('error') or snapshot.get('error', ''))
                item['status'] = ('error' if item['error'] or snapshot['status'] == 'error' else
                                  'stale' if age > self.stale or age < -60 else 'ok')
                item['messageCount'] = sum(q['messageCount'] for q in snapshot['queues']) if snapshot['status'] == 'ok' else None
                for queue in snapshot['queues']:
                    row = {key: val for key, val in queue.items() if key != 'messages'}
                    if selected_queue == queue['identity']:
                        messages = queue.get('messages', [])
                        row.update(messages=messages[(page-1)*50:page*50], capturedMessages=len(messages), page=page)
                    item['queues'].append(row)
            result.append(item)
        return {'nodes': result, 'intervalSeconds': self.interval, 'staleSeconds': self.stale}
