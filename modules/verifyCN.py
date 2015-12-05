'''
initial ldap test module - check how to get, compare and process ldap objects

'''
__author__ = 'Mohammad Kajbaf'
__VERSION__ = '0.9.dev'
from os import fdopen
import ldap
import sys
import time
from kajlib import automain, warning, error, path, getstr
import kajlib
import getpass
import unittest
import argparse
import csv
import tempfile
from handle_ldap import init_ldaps, init_ldap, search_ldap, read_csv

_root = kajlib.path(os.path.dirname(os.path.realpath(__file__)))

class data:
    """
>>> import verifyCN
>>> import ldap
>>> import sys
>>> l = ldap.initialize('')

test for this instead: # l = verifyCN.init_ldaps(verifyCN.data.user, verifyCN.data.passwd, verifyCN.data.dc, DEBUG=True)
>>> isinstance(l, ldap.ldapobject.LDAPObject)
True
    """
    certdir = _root / 'certs'
    certfile = certdir / r'dddddd.pem.cer'
    dc = 't1w063.ddddddd.ir'
    baseDN = "DC=ddddddd,DC=ir"
    baseDN = "OU=DDDDDD Accounts,DC=ddddddd,DC=ir"

    dc2 = 'tew054.ddddddd.ir'
    port2 = 20389
    userTemplate2 = 'eTGlobalUserName=%s,eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta'
    baseDN2 = "eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta"

    searchScope = ldap.SCOPE_SUBTREE

    retrieveAttributes = ['cn', 'displayName', 'sAMAccountName', 'distinguishedName', 'givenName', 'sn']
    retrieveAttributes3 = ['cn', 'displayName', 'sAMAccountName', 'distinguishedName']
    retrieveAttributes2 = ['eTUserid', 'eTFullName', 'eTGlobalUserName', 'eTCustomField10', 'eTFirstName', 'eTLastName']

    Filter = "(&(objectClass=user)(objectcategory=person)(sAMAccountName=%s))"
    Filter3 = "(&(objectClass=group)(sAMAccountName=%s))"
    Filter2 = "(&(objectClass=eTGlobalUser)(eTCustomField10=%s))"

    user = 'mohammad.kaj@ddddddd.ir'
    user2 = 'eTGlobalUserName=Mohammad Kajbaf,eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta'
##    user = None
##    user2 = None
    passwd = 'pppppp'


def get_GUD(l, user_list):
    """queries a provisioning server and return a well-formated dict of dictionaries
    @rtype : dict
    """
    filter = data.Filter2
    result = {}
    for u in user_list:
        #assert not '*' in u
        u = u.lower()
        if '*' in u:
            result[u] = None
            continue
        g_user = search_ldap(l, filter, u, data.baseDN2, attributes=data.retrieveAttributes2)
        #assert len(g_user) == 1
        #result[u] = g_user[0]
        if g_user is None or g_user == []:
            result[u] = None
        else:
            assert len(g_user) > 0
            #if len(g_user) == 1:
            result[u] = g_user[0]
            #else:
            if len(g_user) > 1:
                count = 0
                warning('dup: ' + g_user[0]['eTGlobalUserName'])
                for i in g_user[1:]:
                    count += 1
                    result['%s,%d'%(u,count)] = i
                    warning('dup: ' + i['eTGlobalUserName'])
    return result


def get_AD(l, user_list):
    """queries a Active Directory server and return a well-formated dcit of dictionaries
    @rtype : dict
    """
    filter = data.Filter
    result = {}
    for u in user_list:
        #assert not '*' in u
        u = u.lower()
        if '*' in u:
            result[u] = None
            continue
        g_user = search_ldap(l, filter, u, data.baseDN, attributes=data.retrieveAttributes)
        if g_user is None or g_user == []:
            result[u] = None
        else:
            assert len(g_user) == 1
            result[u] = g_user[0]
    return result


def compare(user_list):
    """compares attributes for a list of users in both AD and GUD and returns the comparison result.
    @rtype : dict
    """
    class AD:
        id = 'sAMAccountName'
        cn = 'cn'
        dn = 'distinguishedName'
        full = 'displayName'
        g = None
        fn = 'givenName'
        sn = 'sn'

    class GUD:
        id = 'eTCustomField10'
        cn = 'eTUserid'
        dn = 'dn'
        full = 'eTFullName'
        g = 'eTGlobalUserName'
        fn = 'eTFirstName'
        sn = 'eTLastName'

    comparison = {}

    l_GUD = init_ldap(data.user2, data.passwd, data.dc2, data.port2, DEBUG=False)
    res_GUD = get_GUD(l_GUD, user_list)
    #assert len(res_GUD) == len(user_list)
    if len(res_GUD) > len(user_list):
        error('duplicate objects exists')

    l_AD = init_ldap(data.user, data.passwd, data.dc, DEBUG=False)
    res_AD = get_AD(l_AD, user_list)
    assert len(res_AD) == len(user_list)

    for u in res_GUD:
        dup = ''
        u_key = u
        if ',' in u:
            u, dup = u.split(',')
        # todo find a better keying method
        u_AD = res_AD[u]
        u_GUD = res_GUD[u_key]

        if u_GUD is None and u_AD is not None:
            comparison[u_key] = ('Not in GUD',
                            {'id': u_AD[AD.id], 'full': u_AD[AD.full], 'cn': u_AD[AD.cn],
                                'dn': u_AD[AD.dn]}
                            )
        elif u_AD is None and u_GUD is not None:
            comparison[u_key] = ('Not in AD',
                            {'id': u_GUD[GUD.id], 'full': u_GUD[GUD.full], 'cn': u_GUD[GUD.cn],
                                'global': u_GUD[GUD.g], 'dn': u_GUD[GUD.dn]}
                            )
        elif u_AD is None and u_GUD is None:
            comparison[u_key] = (None, 'Nonexistent')
        else:
            ### both directories return valid values
            assert isinstance(u_AD, dict)
            assert isinstance(u_GUD, dict)
            comparison_res = {}
            if u_AD[AD.id] != u_GUD[GUD.id]:
                comparison_res['id'] = (u_AD[AD.id], u_GUD[GUD.id])
            if u_AD[AD.full] != u_GUD[GUD.full]:
                comparison_res['full'] = (u_AD[AD.full], u_GUD[GUD.full])
            if u_AD[AD.cn] != u_GUD[GUD.cn]:
                comparison_res['cn'] = (u_AD[AD.cn], u_GUD[GUD.cn])
            if u_AD[AD.fn] != u_GUD[GUD.fn]:
                comparison_res['firstname'] = (u_AD[AD.fn], u_GUD[GUD.fn])
            if u_AD[AD.sn] != u_GUD[GUD.sn]:
                comparison_res['lastname'] = (u_AD[AD.cn], u_GUD[GUD.cn])
            if str.lower(u_AD[AD.cn]) != u_GUD[GUD.g]:
                comparison_res['global user'] = (str.lower(u_AD[AD.cn]), u_GUD[GUD.g])
            if u_AD[AD.id] != u_GUD[GUD.id]:
                comparison_res['id'] = (u_AD[AD.id], u_GUD[GUD.id])

            if comparison_res == {}:
                comparison[u_key] = (None, 'EQ (%s) and (%s)' % (u_AD[AD.dn], u_GUD[GUD.dn])
                                )
            else:
                # todo verify this works fine.
                comparison[u_key] = (','.join(comparison_res.keys()), comparison_res)
        #print '\r\n user %s:' % u
        #print comparison[u]
    return comparison


#@automain
def run_test():
    """
    runs the unittest.main
    @return: None
    """
    unittest.main()


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.openfiles = []
        self.files = []
        data.user = 'mohammad.kaj@ddddddd.ir'
        data.user2 = data.userTemplate2 % 'Mohammad Kajbaf'
        data.passwd = 'Cosk3sheG9z00'

    def tearDown(self):
        data.l_GUD = data.l_AD = None
        data.user = data.user2 = data.passwd = None
        sys.stdin = sys.__stdin__
        for f in self.openfiles:
            f.close()
        for f in self.files:
            try:
                f.delete()
            except:
                pass

    def test_0(self):
        l = ldap.initialize("ldap://%s:%d"%('localhost', 636))
        self.assertIsInstance(l, ldap.ldapobject.LDAPObject)

    def test_AD_LDAP(self):
        l = init_ldap(data.user, data.passwd, data.dc, DEBUG=False)
        self.assertIsInstance(l, ldap.ldapobject.LDAPObject)

    def test_GUD_LDAP(self):
        l = init_ldap(data.user2, data.passwd, data.dc2, data.port2, DEBUG=False)
        self.assertIsInstance(l, ldap.ldapobject.LDAPObject)

    def test_AD_Search(self):
        l = init_ldap(data.user, data.passwd, data.dc, DEBUG=False)
        result = search_ldap(l, data.Filter, 'mohammad.ka*', data.baseDN, data.searchScope, data.retrieveAttributes, DEBUG=False)
        #print result[0]
        self.assertIsInstance(result, list)

    def test_GUD_Search(self):
        l = init_ldap(data.user2, data.passwd, data.dc2, data.port2, DEBUG=False)
        result = search_ldap(l, data.Filter2, 'mohammad.ka*', data.baseDN2, data.searchScope, data.retrieveAttributes2, DEBUG=False)
        #print result[0]
        self.assertIsInstance(result, list)

    def test_get_GUD(self):
        b1 = 'Bilakh'
        b2 = 'Bilakh*'
        user_list = ['AKBAR.N', 'ALI.DANA', b1]
        l = init_ldap(data.user2, data.passwd, data.dc2, data.port2, DEBUG=False)
        res = get_GUD(l, user_list)
        self.assertEquals(len(res), 3)
        for u in res:
            print '\r\n user %s:' % u
            if res[u]:
                for k in res[u]:
                    print k, res[u][k]
                    self.assertIsInstance(res[u][k], str)
            else:
                #print '\t is None'
                self.assertIsNone(res[u])
        self.assertIsNone(res[b1.lower()])
        #self.assertRaises(AssertionError, get_GUD, l, [b2])
        res = get_GUD(l, [b2])
        self.assertIsNone(res[b2.lower()])

    def test_get_AD(self):
        b1 = 'Bilakh'
        b2 = 'Bilakh*'
        user_list = ['AKBAR.N', 'ALI.DANA', b1]
        l = init_ldap(data.user, data.passwd, data.dc, DEBUG=False)
        res = get_AD(l, user_list)
        self.assertEquals(len(res), 3)
        for u in res:
            print '\r\n user %s:' % u
            if res[u]:
                for k in res[u]:
                    print k, res[u][k]
                    self.assertIsInstance(res[u][k], str)
            else:
                self.assertIsNone(res[u])
                #print '\t is None'
        self.assertIsNone(res[b1.lower()])
        #self.assertRaises(AssertionError, get_AD, l, [b2])
        res = get_AD(l, [b2])
        self.assertIsNone(res[b2.lower()])

    def test_comparison(self):
        b1 = 'Bilakh'
        b2 = 'Bilakh*'
        user_list = ['AKBAR.N', 'ALI.DANA', b1]

        comparison = compare(user_list)
        self.assertIsInstance(comparison, dict)
        self.assertEqual(len(comparison), len(user_list))
        self.assertIsNone(comparison[b1.lower()][0])

        #self.assertRaises(AssertionError, compare, [b2])
        comparison = compare([b2])
        self.assertIsNone(comparison[b2.lower()][0])

    def test_parese_login(self):
        sys.argv = r'verifyCN.py -u mohammad.kaj -p Cosk3sheG9z00 -f IFS_Employee_Changes_06-22-2014.csv'.split(' ')
        user_list = parse_input()
        self.assertIsInstance(user_list, list)
        self.assertTrue(user_list)
        sys.argv = r'verifyCN.py -u mohammad.kaj -p Cosk3sheG9z00 -f AD_Employee_Result_06-22-2014.csv'.split(' ')
        user_list = parse_input()
        self.assertIsInstance(user_list, list)
        self.assertTrue(user_list)
        #sys.argv = r'verifyCN.py -u mohammad.kaj -p Cosk3sheG9z00 -f -'.split(' ')
        #user_list = parse_input()
        #self.assertIsInstance(user_list, list)
        #self.assertTrue(user_list)
        t_in = tempfile.TemporaryFile()
        self.openfiles.append(t_in)
        with tempfile.NamedTemporaryFile(delete=False) as t_list:
            t_list.write('LogonName\r\ntest')
            self.openfiles.append(t_list)
            t_p = kajlib.path(t_list.name)
            self.files.append(t_p)
        #id_list, t_p = tempfile.mkstemp()
        #t_list = fdopen(id_list, 'w+b')
        #t_list.write('LogonName\r\ntest')
        #t_list.close()
        t_in.write(t_p.target)
        t_in.seek(0)
        sys.stdin = t_in
        sys.argv = r'verifyCN.py -u mohammad.kaj -p Cosk3sheG9z00 -f *'.split(' ')
        user_list = parse_input()
        self.assertEqual(user_list, ['test'])


def parse_input():
    """
    parse input and elicit login information and search criteria.
    puts login info in public data class and returns search items as list.
    @return: list
    """
    parser = argparse.ArgumentParser(description='A script to process and compare differences between Active Directory'
                                                 'and Global User Directory')
    parser.add_argument('-u','--username', help='username', required=False)
    parser.add_argument('-p','--password', help='password', required=False)
    group = parser.add_mutually_exclusive_group(required=True, default='2015-08-08')
    #group.add_argument('-s','--sAmAccountName', help='a specific username')
    group.add_argument('-l','---user-list', metavar='username', help='a comma seperated list of users', nargs='*')
    group.add_argument('-f','--file', #default='-',
                       help='csv file for user names, * to ask for filename, - to read from stdin'
                       )
    parser.add_argument("-t", "--test", help="run unittests", action="store_true")
    cmd = parser.parse_args()
    #args = vars(parser.parse_args())

    if cmd.username is None:
        if not cmd.test:
            try:
                username = getpass.getuser()
                print 'no user provided, trying to log in as %s' % username
            except:
                error('A username must be provided')
                raise 'unknown username'
        else:
            username = None
    else:
        username = cmd.username
    if username and not '@' in username:
        username += '@ddddddd.ir'
    data.user = username

    if cmd.password is None:
        if not cmd.test and cmd.file != '-':
            password = getpass.getpass()
        else:
            password = None
    else:
        password = cmd.password
    data.passwd = password

    if cmd.user_list:
        user_list = cmd.user_list
    elif cmd.file:
        data.file = None
        if cmd.file == '*':
            data.file = kajlib.path(getstr('enter csv filename, or drag the file here: '))
        else:
            data.file = kajlib.path(cmd.file)
        if cmd.file == '-':
            user_list = read_csv(sys.stdin)
        elif data.file and data.file.isfile():
            with data.file.open(mode='rb') as user_csv:
                user_list = read_csv(user_csv)
        else:
            raise 'wrong file or path name'
    else:
        raise 'please define the search criteria'

    if cmd.test:
        data.list = user_list
        sys.argv = [__file__]
        run_test()
        sys.exit()
    return user_list


def login():
    """
    logs in to the Active Directory and Provisioning Server and stores LDAP objects in public data class.
    @return: None
    """
    try:
        assert data.user is not None
        assert data.passwd is not None
        assert not '*' in data.user
        assert '@' in data.user
    except:
        raise 'login information not set or are incorrect'

    try:
        #data.l_AD = init_ldaps(data.user, data.passwd, data.dc)
        data.l_AD = init_ldap(data.user, data.passwd, data.dc)
        login1 = (
                search_ldap(data.l_AD, '(userPrincipalName=%s)', data.user, data.baseDN,
                            attributes=['sAMAccountName', 'userPrincipalName', 'cn'])
                    )[0]
        assert data.user == login1['userPrincipalName']

    except Exception as e:
        error('invalid username or password')
        raise e
    warning(u'%s logged in to Active Directory Server' % data.l_AD.whoami_s())

    data.user2 = data.userTemplate2 % login1['cn']
    try:
        data.l_GUD = init_ldap(data.user2, data.passwd, data.dc2, data.port2)
        login2 = (
            search_ldap(data.l_GUD, '(eTGlobalUserName=%s)', login1['cn'], data.baseDN2,
                        attributes=['eTCustomField10', 'eTGlobalUserName'])
                    )[0]
    except Exception as e:
        error("Provisioning server access denied or Global user doesn't exists")
        raise e

    assert login1['sAMAccountName'].lower() == login2['eTCustomField10'].lower()
    assert login1['cn'].lower() == login2['eTGlobalUserName'].lower()
    warning('%s logged in to the Provisioning Server' % login2['eTGlobalUserName'])
    data.l_AD.__enter__ = lambda: data.l_AD
    data.l_AD.__exit__ = lambda x,y,z: data.l_AD.unbind_s()
    return data.l_AD


@automain
def main():
    user_list = parse_input()
    login()
    comparison = compare(user_list)
    #print '- ' * 15 + '\r\nlist of all processed users\r\n'
    #print comparison
    print '\r\n' + '- ' * 15 + ' \r\nlist of inconsistent users\r\n'
    for comp in comparison:
        res, val = comparison[comp]
        # todo: check output format; done
        if res:
            print '\r\n++ %s:\t%s,' % (comp, res)
            for k in val:
                if k != 'dn':
                    print k, val[k]
    # todo verify the result list with input file (function verify_csv)
    print '\r\nPress Enter to continute...'
    raw_input('')