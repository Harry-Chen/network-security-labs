
def stat(cat):
    with open('alexa/{}.txt'.format(cat), 'r') as f:
        all_names = list(map(lambda s: s.strip(), f))
    with open('{}_pollute_report.txt'.format(cat), 'r') as f:
        polluted_names = set(map(lambda s: s.strip(), f))
    with open('{}_pollute_stat.txt'.format(cat), 'w') as f:
        def do_top(n):
            f.write('{} of {} names are polluted!\n'.format(len(polluted_names & set(all_names[:n])), n))
        do_top(10)
        do_top(100)
        do_top(500)

stat('global')
stat('computer')