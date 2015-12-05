import os
import kajlib

"""
for i in users:
	print i
	
alireza.ghah
anousha.s
ario.j
behzad.rou
ehsan.hon
khashayar.a
majid.kha
mehdi.mehra
mirsoheil.a
narmin.m
omid.mo
saman.se
soheil.n
meisam.soh
seuneh.b
azadeh.ha

for i in base_users2:
	print i['eTGlobalUserName'],i['eTPassword']
	
alireza.ghah saj!92Rnij
anousha.s ApikW84Yfes
ario.j rahHWqep
behzad.rou EyejH58Thas
ehsan.hon AgawT56_geg
khashayar.a biqHTtew
majid.kha siqC28Hhic
mehdi.mehra Ahap@Hziv
mirsoheil.a Ayat?Frey
narmin.m Ewen$64Bmar
omid.mo megDDpiw
saman.se EdadMJsaj
soheil.n yegFRsef
meisam.soh Egaj#97?jin
seuneh.b kegT84Lqam
azadeh.ha rayDZqik
mohammad.eb viy@96@qaj
"""

_root = kajlib.path(os.path.join(os.path.dirname(os.path.realpath(__file__)),'../files'))
users = (_root / 'users.lst').open('r').read()
base_users2 = (_root / 'base_users.lst').open('r').read()
domain = r'ddd.ddd'

base_users = []
ignore = []
for i in users:
	try:
		u = ImportRoles.search_ldap(l53,'(eTGlobalUserName=%s)',i ,'eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta',1,['eTCustomField08', 'eTCustomField09', 'eTCustomField10', 'eTFullName', 'eTFirstName', 'eTGlobalUserName', 'eTPassword', 'eTPasswordExpirationDate'])
	except:
		print 'Igonoring ', i
	else:
		assert len(u) == 1
		u = u[0]
		u['eTPassword'] = nicepass.nicepass(6,2,5)
		print 'user: %s,\tCF08: %s,\tCF09: %s'%(i, u['eTCustomField08'], u['eTCustomField09'])
		base_users.append(u)


for i in base_users:
	mod = [(ldap.MOD_REPLACE, 'eTPassword', i['eTPassword']), (ldap.MOD_REPLACE, 'eTPasswordExpirationDate', '0000000000')]
	try:
		l53.modify_s(i['dn'], mod)
	except:
		ignore.append((i['dn'], i['eTGlobalUserName']))


with (_root / 'users.csv').open('w') as f:
	writer = csv.DictWriter(f, base_users[0].keys() + ['EMail'])
	writer.writeheader()
	for i in base_users2:
		i['EMail'] = '%s <%s@%d>'%(i['eTFullName'],i['eTGlobalUserName'],domain)
		writer.writerow(i)

