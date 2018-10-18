import re

REGEX = re.compile(r'<a href\="/siteinfo/.+">(.+)</a>')

def gather(dir):
    result = []
    for i in range(20):
        with open('{}/{}.html'.format(dir, i), 'r') as f:
            html = f.read()
        for m in REGEX.finditer(html):
            result.append(m.group(1).lower())
    with open('{}.txt'.format(dir), 'w') as f:
        f.write('\n'.join(result) + '\n')

gather('global')
gather('computer')
