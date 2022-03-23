import json
from docopt import docopt

from bigip_utils.logger import logger
from bigip_utils.bigip import *
#
# This script enforces all attack signatures that are ready to be enforced:
#   https://support.f5.com/csp/article/K60640453?utm_source=f5support&utm_medium=RSS
#

__doc__ = """
    Usage:
        enforce-ready-signatures.py [-hvndsb] [-p POLICY_NAME] -l LIST_FILE

    Options:
        -h --help                                   Show this screen.
        -v --version                                Show version.
        -n --dry-run                                Show actions. Do not execute them.
        -s --sync                                   Sync devices after changes.
        -b --backup-config                          Create and download a UCS file.
        -d --dev-devices-only                       Skip non DEV devices.
        -l LIST_FILE --list-file=LIST_FILE          CSV file with list of bigips. Format: hostname,ip,username,password
        -p POLICY_NAME --policy-name=POLICY_NAME    Name of a policy to act on. [default: all]
"""
VERSION = "0.2"


def enforce_ready_signatures(bigip, id):
    params = {
        '$select': '',
        '$filter': 'hasSuggestions eq false AND wasUpdatedWithinEnforcementReadinessPeriod eq false and performStaging eq true',
    }
    data = {'performStaging': 'false'}
    url_base_asm = f'https://{bigip.ip}/mgmt/tm/asm/policies/{id}/signatures'
    json_data = bigip.patch(url_base_asm, params=params, data=json.dumps(data))
    count = int(json_data.get('totalItems', 0))
    return count


def get_ready_signatures_count(bigip, id):
    params = {
        '$select': '',
        '$filter': 'hasSuggestions eq false AND wasUpdatedWithinEnforcementReadinessPeriod eq false and performStaging eq true',
        '$top': '1',
    }
    url_base_asm = f'https://{bigip.ip}/mgmt/tm/asm/policies/{id}/signatures'
    json_data = bigip.get(url_base_asm, params=params)
    # for d in json_data['items']:
    #     results[d['signatureReference']['name']] = d['signatureReference']['signatureId']
    count = int(json_data.get('totalPages', 0))
    return count


def process_device(bigip, dry_run=True, policy=None, sync_device_group=None):
    policies_virtuals = get_virtuals_asm_policies(bigip)
    policies=bigip.get_asm_policies()
    enforced_signatures_count = 0
    ready_signatures = {}
    for i in policies:
        if(i['type'] == 'parent'):
            continue
        policy_id = i['id']
        policy_name = i['name']
        policy_virtuals = policies_virtuals[policy_name]
        if not policy == 'all' and not policy == policy_name:
            continue
        if(i['enforcementMode'] == 'blocking'):
            ready_signatures[policy_name] = get_ready_signatures_count(
                bigip, policy_id)
            if ready_signatures[policy_name] and dry_run:
                logger.info(
                    f"{bigip.hostname}: [DRY-RUN] : {policy_name}: Enforcing {ready_signatures[policy_name]} ready attack signatures. VIPs={len(policy_virtuals)}")
            elif ready_signatures[policy_name]:
                logger.info(
                    f"{bigip.hostname}: {policy_name}: Enforcing {ready_signatures[policy_name]} ready attack signatures.  VIPs={len(policy_virtuals)}")
                count = enforce_ready_signatures(bigip, policy_id)
                if count:
                    r = apply_asm_policy(bigip, policy_id)
                    if not r:
                        logger.error(
                            f"{bigip.hostname}: Applying policy {policy_name} did not complete successfully.")
                enforced_signatures_count += count
    if enforced_signatures_count and sync_device_group:
        logger.info(f"{bigip.hostname}: Syncing device group.")
        sync_devices(bigip, device_group=sync_device_group)
    return enforced_signatures_count


if __name__ == "__main__":
    arguments = docopt(__doc__, version=VERSION)
    devices_file = arguments['--list-file']
    dry_run = arguments['--dry-run']
    dev_only = arguments['--dev-devices-only']
    policy_name = arguments['--policy-name']
    sync = arguments['--sync']
    backup_config = arguments['--backup-config']
    
    for (hostname, ip, username, password) in get_bigips(devices_file, dev_only=dev_only):
        b = BigIP(hostname, username, password, ip=ip, verify_ssl=False)
        logger.info(
            f"{b.hostname}: Started. Policy: {policy_name} Dry-Run: {dry_run}")
        proceed = True
        check_active(b)
        device_group = get_asm_sync_group(b)
        if not device_group and not check_standalone(b):
            logger.error(
                f"{b.hostname}: Could not find ASM device group name. {device_group}")
            proceed = False
        elif device_group:
            logger.info(f"{b.hostname}: Sync Device Group: {device_group}")
        if (not b.token):
            logger.warning(
                f'{b.hostname}: Unable to obtain authentication token')
            proceed = False
        if not check_active(b):
            logger.warning(f'{b.hostname}:  Not active, skipping device.')
            proceed = False
        enforced_signatures_count = 0
        get_ucs(b,overwrite=True)
        if proceed:
            if backup_config and not dry_run:
                get_ucs(b,overwrite=True)
            enforced_signatures_count = process_device(
                b, dry_run=dry_run, policy=policy_name, sync_device_group=device_group)
        logger.info(
            f"{b.hostname}: Finished. enforced signatures count: {enforced_signatures_count}")
    logger.info("Done.")
