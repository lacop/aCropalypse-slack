# Download all files uploaded to slack by a user
#
# First, get a token with file read access:
# - Create new Slack app
# - Go to "OAuth & Permissions"
#   - Add "User Token Scopes" for "files:read"
#   - Install the app to workspace
#   - Copy the "OAuth token"
# Then run:
# export SLACK_USER_TOKEN=xoxp-...
# mkdir dump
# python3 slack_list.py dump U12345

import backoff
import humanize
import json
import os
import requests
import sys
import time
import tqdm
from types import SimpleNamespace
from slack_bolt import App

token = os.environ.get("SLACK_USER_TOKEN")
app = App(token=token)

dump_dir = sys.argv[1]
user = sys.argv[2]
if not os.path.isdir(dump_dir):
    print('usage: <foo> output_dump_dir userid', file=sys.stderr)
    sys.exit(1)

page = 1
all_files = []
while True:
    l = app.client.files_list(user=user, page=page)
    assert(l.data['ok'] == True)
    all_files += l.data['files']
    print(l.data['paging'])
    page += 1
    if page > l.data['paging']['pages']:
        break
print(len(all_files))

files = {}
for file_entry in all_files:
    if 'mode' in file_entry and file_entry['mode'] == 'tombstone':
        continue
    f = SimpleNamespace()
    f.name = file_entry['name'] 
    f.url = file_entry['url_private']
    f.size = file_entry['size']
    f.type = file_entry['filetype']
    f.all = file_entry 
    files[file_entry['id']] = f

def print_stats(files):
    print('Total files:', len(files))
    print('Total size:', humanize.naturalsize(sum(x.size for x in files.values()), binary=True))
print_stats(files)

print('\nChecking what we already have')
total, needed = 0, 0
for file in os.listdir(dump_dir):
    id = file.split('.')[0]
    total += 1
    if id in files:
        del files[id]
        needed += 1
print(f'Already have {needed} needed files we can skip ({total} total)')
print_stats(files)

headers = {
    'Authorization': f'Bearer {token}'
}

@backoff.on_exception(backoff.expo, Exception)
def download(file):
    try:
        res = requests.get(file.url, headers=headers)
    except e:
        print('Exception', e)
        raise e
    if len(res.content) != file.size:
        print('Length mismatch', file, len(res.content))
        # looks like slack recompressed jpegs, if it seems close enough
        # accept it anyway
        #print(file.all)
        if file.type == 'jpg' and len(res.content)*1.1 >= file.size:
            return res.content
        return None
    return res.content

print('\n\nDOWNLOADING')
for id, file in tqdm.tqdm(files.items()):
    c = download(file)
    if c is None:
        continue
    path = os.path.join(dump_dir, f'{id}.{file.type}')
    if len(c) != file.size:
        path = os.path.join(dump_dir, f'short-{id}.{file.type}')
    with open(path, 'wb') as f:
        f.write(c)
    time.sleep(1)