import csv
import json
from pickle import BINFLOAT
import time
import requests
import os
import re
from logger import logger

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_bigips(fn, dev_only=True):
    username = os.environ.get('BIGIP_USERNAME')
    password = os.environ.get('BIGIP_PASSWORD')

    with open(fn, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and not row[0].startswith('#'):
                if not row[1]:
                    row[1] = row[0]
                if not row[2]:
                    row[2] = username
                if not row[3]:
                    row[3] = password
                if dev_only and not 'DEV' in row[0]:
                    continue
                yield row


class Downloader:
    # File is assumed to be in /shared/images directory.
    # TODO: if filename is an abolute path, maybe move it automatically to /shared/images
    def __init__(self, bigip=None, filename=None, download_dir=None,overwrite=False):
        if None in (bigip, filename, download_dir):
            raise Exception("Missing bigip, filename or download directory")
        base_dir = "/var/config/rest/downloads"
        url_path = "/mgmt/shared/file-transfer/uploads"
        base_dir2 = "/shared/images"
        url_path2 = "/mgmt/cm/autodeploy/software-image-downloads"
        self.bigip = bigip
        self.download_dir = download_dir
        self.overwrite=overwrite
        self.filename = filename
        self.local_filename = os.path.join(download_dir, filename)
        self.chunk_size = 512 * 1024
        self.url = f'https://{bigip.ip}/mgmt/cm/autodeploy/software-image-downloads/{filename}'
        self.file_size = self.get_file_size()
        if self.file_size:
            self.download()
        else:
            logger.error(
                f"{bigip.hostname}: {filename} does not exist on the BIGIP.")

    def get_file_size(self):
        start = 0
        end = self.chunk_size - 1
        size = 0
        content_range = "%s-%s/%s" % (start, end, size)
        headers = {'Content-Range': content_range}
        resp = self.bigip.get(self.url, headers=headers, stream=True)
        try:
            crange = resp.headers.get('Content-Range')
            size = int(crange.split('/')[-1])
        except Exception as e:
            size = 0
        return size

    def download(self):
        c = 0
        while True:
            c += 1
            try:
                r = self._download()
            except Exception as e:
                r = False
                logger.warning(
                    f"{self.bigip.hostname}: Exception: {e}. Retrying...")
                time.sleep(30)
                self.bigip.reset()
            if r:
                logger.info(f"{self.bigip.hostname}: Download completed.")
                break
            elif c > 10:
                logger.error(f"{self.bigip.hostname}: Giving up on download.")
                raise Exception("Download failed")
            else:
                logger.warning(
                    f"{self.bigip.hostname}: Download failed. Retrying...")

    def _download(self):
        ok = False
        if os.path.exists(self.local_filename) and not self.overwrite:
            self.local_file_size = os.path.getsize(self.local_filename)
            mod = 'ab'
            start = self.local_file_size
            if self.local_file_size == self.file_size:
                logger.debug(
                    f"{self.bigip.hostname}: Skipping download of {self.local_filename}")
                return True
            else:
                logger.debug(
                    f"{self.bigip.hostname}: Resuming download of {self.local_filename}")
        else:
            logger.debug(
                f"{self.bigip.hostname}: Starting download of {self.local_filename}")
            self.local_file_size = 0
            mod = 'wb'
            start = 0
        end = start + self.chunk_size - 1
        size = self.file_size - 1
        if end > size:
            end = size
        current_bytes = start
        with open(self.local_filename, mod) as f:
            while True:
                content_range = f"{start}-{end}/{size}"
                headers = {'Content-Range': content_range}
                resp = self.bigip.get(self.url, headers=headers, stream=True)
                crange = resp.headers['Content-Range']
                a, b, c = [int(x) for x in re.split('\-|/', crange)]
                # logger.debug(
                #     f"{self.bigip.hostname}: Got {(b-a):,} bytes out of {c:,} Remaining: {(c-b):,}")
                if resp.status_code == 200:
                    current_bytes += self.chunk_size
                    for chunk in resp.iter_content(self.chunk_size):
                        f.write(chunk)
                    if end == size:
                        ok = True
                        break
                else:
                    logger.warning(
                        f"{self.bigip.hostname}: unexpected status_code: {resp.status_code}")
                    break
                start += self.chunk_size
                if self.chunk_size > size:
                    end = size
                if (current_bytes + self.chunk_size) > size:
                    end = size
                else:
                    end = start + self.chunk_size - 1
        return ok


class BigIP:
    def __init__(self, hostname, username, password, ip=None, verify_ssl=True):
        self.hostname = hostname
        self.ip = ip if ip else hostname
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token = None
        self._session = None

    @property
    def session(self):
        if not self._session:
            self._session = requests.session()
            self._session.verify = self.verify_ssl
            self._session.headers.update({'X-F5-Auth-Token': self.token})
        return self._session

    @property
    def token(self):
        if not self._token:
            body = {
                'username': self.username,
                'password': self.password,
                'loginProviderName': 'tmos'
            }

            token_response = requests.post(
                f'https://{self.ip}/mgmt/shared/authn/login',
                verify=self.verify_ssl,
                auth=(self.username, self.password), json=body) \
                .json()

            self._token = token_response['token']['token']
        return self._token

    def upload_file(self, file_path, remote_dir="/var/tmp"):
        # Uploaded files end up in: /var/config/rest/downloads

        headers = {
            'Content-Type': 'application/octet-stream',
            'X-F5-Auth-Token': self.token
        }

        chunk_size = 512 * 1024
        file_obj = open(file_path, 'rb')
        file_name = os.path.basename(file_path)
        size = os.path.getsize(file_path)
        end_point = 'https://' + self.ip + \
            '/mgmt/shared/file-transfer/uploads/' + file_name

        start = 0

        while True:
            file_slice = file_obj.read(chunk_size)
            if not file_slice:
                break

            current_bytes = len(file_slice)
            if current_bytes < chunk_size:
                end = size
            else:
                end = start + current_bytes

            content_range = f'{start}-{end - 1}/{size}'
            headers['Content-Range'] = content_range
            requests.post(end_point,
                          data=file_slice,
                          headers=headers,
                          verify=self.verify_ssl)
            start += current_bytes
        if remote_dir:
            return self.run_bash_command(f'mv /var/config/rest/downloads/{file_name} remote_dir')

    def download_file(self, filename, download_dir=None,overwrite=None):
        d = Downloader(self, filename=filename, download_dir=download_dir,overwrite=overwrite)

    def run_bash_command(self, command):

        headers = {
            'X-F5-Auth-Token': self.token
        }

        payload = {
            'command': 'run',
            'utilCmdArgs': f"-c '{command}'"
        }

        response = requests.post('https://' + self.ip + '/mgmt/tm/util/bash', json=payload, verify=self.verify_ssl,
                                 headers=headers).json()
        if 'commandResult' in response:
            logger.debug(f"{self.hostname}: Command: {command}")
            logger.debug(
                f"{self.hostname}: Result: {response['commandResult']}")
            return re.sub('\n$', '', response['commandResult'])
        else:
            return None

    def test_remote_file(self, file_path):
        return self.run_bash_command(f'[ -f "{file_path}" ] && echo 1 || echo 0') == '1'

    def post(self, uri, params={}, data={}, **kwargs):
        json_data = {}
        if uri.startswith('https:'):
            url_base = uri.replace('https://localhost', f"https://{self.ip}")
        else:
            url_base = f'https://{self.ip}{uri}'
        self.session.headers.update({'Content-Type': 'application/json'})
        r = self.session.post(url_base, params=params,
                              data=json.dumps(data), **kwargs)
        if 'json' in r.headers['content-type'].lower():
            json_data = r.json()
        else:
            json_data = r
        return json_data

    def get(self, uri, params={}, **kwargs):
        json_data = {}
        if uri.startswith('https:'):
            url_base = uri.replace('https://localhost', f"https://{self.ip}")
        else:
            url_base = f'https://{self.ip}{uri}'
        r = self.session.get(url_base, params=params, **kwargs)
        if 'json' in r.headers['content-type'].lower():
            json_data = r.json()
        else:
            json_data = r
        try:
            self.session.headers.pop('Content-Range')
        except KeyError:
            pass
        return json_data


def await_task(bigip, task_id, retries=10, sleep_time=10):
    url_base = f'https://{bigip.ip}/mgmt/tm/asm/tasks/apply-policy/{task_id}'
    task_status = False
    task_status = False
    for i in range(1, retries+1):
        r = bigip.get(url_base)
        if r.ok:
            r_json = r.json()
            task_status = r_json.get('status')
            if task_status == 'COMPLETED':
                return True
            else:
                logger.debug(f"{bigip.ip}: task status: {task_status}")
        time.sleep(sleep_time)
    return False


def check_active(bigip):
    json_data = bigip.get("/mgmt/tm/sys/global-settings",
                          params={"$select": "hostname"})
    hostname = json_data.get('hostname')

    json_data = bigip.get("/mgmt/tm/cm/traffic-group/traffic-group-1/stats",
                          params={"$select": "deviceName,failoverState"})
    for i in json_data.get('entries', []):
        devices = json_data['entries'][i]['nestedStats']
        device = devices['entries']['deviceName']['description']
        state = devices['entries']['failoverState']['description']
        if (hostname in device) and ('active' in state):
            return True
    return False


def check_standalone(bigip):
    json_data = bigip.get('/mgmt/tm/cm/sync-status')
    for i in json_data.get('entries', []):
        devices = json_data['entries'][i]['nestedStats']
        state = devices['entries']['mode']['description']
        if state == 'standalone':
            return True
    return False


def get_asm_sync_group(bigip):
    device_groups = []
    if not check_standalone(bigip):
        url_base = f'https://{bigip.ip}/mgmt/tm/cm/device-group'
        json_data = bigip.get(url_base)
        for dg in json_data['items']:
            if dg['asmSync'] == "enabled":
                device_groups.append(dg['name'])
    if len(device_groups) == 1:
        return device_groups[0]
    else:
        return None


def sync_devices(bigip, device_group=None):
    if not device_group:
        return False
    url_base = f'https://{bigip.ip}/mgmt/tm/cm/config-sync'
    data = {
        "command": "run",
        "options": [{"to-group": device_group}, ],
    }
    r = bigip.post(url_base, data=json.dumps(data))
    return r.ok


def get_ucs(bigip, delete_remote_copy=False, overwrite=False):
    """
        Create a UCS file and downloads it. Optionally deletes the remote copy.
    """
    ucs_filename = f"{bigip.hostname}.ucs"
    ucs_filename_full = f"/shared/images/{ucs_filename}"
    command = f"echo tmsh save /sys ucs {ucs_filename_full}"
    logger.debug(f"{bigip.hostname}: Creating UCS file...")
    result = bigip.run_bash_command(command)
    logger.debug(
        f"{bigip.hostname}: Downloading UCS file: {ucs_filename_full}")
    bigip.download_file(ucs_filename, download_dir="/tmp",overwrite=overwrite)
    if delete_remote_copy:
        command = f"rm {ucs_filename_full}"
        logger.debug(
            f"{bigip.hostname}: Deleting UCS file: {ucs_filename_full}")
        result = bigip.run_bash_command(command)


def get_asm_policies(bigip):
    url_base_asm = f'https://{bigip.ip}/mgmt/tm/asm/policies'
    params = {
        '?$select': 'id,name,enforcementMode,type',
    }
    return bigip.get(url_base_asm, params=params)['items']


def get_virtuals_asm_policies(bigip):
    """
        Returns a dict of policy_name --> virtual servers
    """
    params = {
        '$select': 'name,virtualServers,manualVirtualServers',
        # '$filter': "attachedPoliciesReferences/link eq '*'",
    }
    url_base_asm = f'https://{bigip.ip}/mgmt/tm/asm/policies'
    json_data = bigip.get(url_base_asm, params=params)
    json_data['items'][0]['name']
    result = {}
    for d in json_data['items']:
        name = d.get('name')
        result[name] = d.get('virtualServers', [])
    return result


def apply_asm_policy(bigip, policy_id):
    """
        Applies the given ASM policy and waits for task to complete
    """
    url_base_asm = f'https://{bigip.ip}/mgmt/tm/asm/tasks/apply-policy'
    data = {"policyReference": {
        "link": f"https://{bigip.ip}/mgmt/tm/asm/policies/{policy_id}"}}
    task_status = False
    r_json = bigip.post(url_base_asm, data=json.dumps(data))
    task_id = r_json.get('id')
    if task_id:
        task_status = await_task(
            bigip, task_id, retries=10, sleep_time=10)
    return task_status


if __name__ == '__main__':
    devices_file = "bigips.csv"
    for (hostname, ip, username, password) in get_bigips(devices_file, dev_only=False):
        b = BigIP(hostname, username, password, verify_ssl=False)
        get_ucs(b)
        logger.info(f"Standalone: {check_standalone(b)}")
        logger.info(f"Active: {check_active(b)}")
        logger.info(f"ASM Sync Group: {get_asm_sync_group(b)}")
        logger.info(
            f'Download file: {b.download_file(filename="passwd",download_dir="/tmp")}')
    logger.info("Done.")
