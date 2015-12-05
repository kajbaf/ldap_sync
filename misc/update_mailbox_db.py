"""
@author: Mohammad Kajbaf
@date: 2015-07-12
@revision: 1

Generate name of Exchange DBs based on Job-level, office, department for ActiveDirectory users.
"""
rep_map = {'.': ' ',
          'IS': '-',
          'JL': 'Level-',
          'TE': 'TehranEast',
          'TW': 'TehranWest',
          'TMP': '(Temp)',
          'VEN': 'Vendor'}

def generate_db_title(dbs, mapping):
    res = []
    for d in dbs:
        o_d = d
        for k,v in mapping.iteritems():
            d = d.replace(k, v)
        res.append('%s;%s'%(o_d, d))
    return res

print ("Please enter list of mailboxes")
dbs = []
s = '.'
while s:
    s = raw_input()
    if s and s != '.':
        dbs.append(s)
    if s == '.':
        break

db_titles = generate_db_title(dbs, rep_map)
db_titles.sort()
print (";(Select MailBox Database)")
for t in db_titles:
    print t




'''
TE.IS.JL1.02
TE.IS.JL1.07
TE.IS.JL2.01
TE.IS.JL2.02
TE.IS.JL2.03
TE.IS.JL2.10
TE.IS.JL3.01
TE.IS.JL3H.03
TE.IS.VEN.15
TW.IS.JL1.07
TW.IS.JL2.02
TE.IS.TMP.01
TE.IS.TMP.02
TW.IS.TMP.09
'''