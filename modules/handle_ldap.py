'''
Provides facilities to login to ldap servers, search them and create new objects. Includes static data.
@author: Mohammad Kajbaf
@changelist:
1.2: separate logins for ps and active.
'''
__author__ = 'Mohammad Kajbaf'
__version__ = '1.2'

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
from LDAPHelper import *

_root = kajlib.path(os.path.dirname(os.path.realpath(__file__)))
convert_manager = lambda manager: manager.replace(',DC=dddddd,DC=ir', ',EndPoint=DDDDDDD Active Directory,Namespace=ActiveDirectory,Domain=im,Server=Server').replace(',OU=',',ADSOrgUnit=').replace('CN=','Account=')
revert_manager = lambda manager: manager.replace(',EndPoint=DDDDDDD Active Directory,Namespace=ActiveDirectory,Domain=im,Server=Server', ',DC=dddddd,DC=ir').replace(',ADSOrgUnit=', ',OU=').replace('Account=','CN=')

class data:

    certdir = _root / 'certs'
    certfile = certdir / r'dddddd.pem.cer'

    dc = 'tew053.ddddddd.ir'
##    dc = 'tevw068.ddddddd.ir'
    dc2 = 'ddddddd.ir'
    port = 20389
    
    userTemplate = 'eTGlobalUserName=%s,eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta'
    roleTemplate = 'eTRoleName=%s,eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
    roleNameTemplate = 'eTRoleName'
    roleType = ['eTRole']
    baseDN = "eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta"
    baseDN2 = "DC=ddddddd,DC=ir"
    baseDNRole = 'eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
    searchScope = ldap.SCOPE_SUBTREE

    roleAttributes = ['eTRoleName', 'eTDescription', 'eTComments', 'eTDepartment', 'eTCustomField01', 'eTCustomField02', 'eTCustomField03']

    userFilter = "(&(objectClass=eTGlobalUser)(eTGlobalUserName=%s))"
    userFilter2 = "(&(objectClass=user)(sAMAccountName=%s))"
    roleFilter = "(&(objectClass=eTRole)(eTRoleName=%s))"

    user = 'mohammad.kaj'
##    user = 'mk'
    usersuffix = '@ddddddd.ir'

##    retrieveAttributes = ['cn', 'displayName', 'sAMAccountName', 'distinguishedName', 'givenName', 'sn', 'memberOf']
##    retrieveAttributes3 = ['cn', 'displayName', 'sAMAccountName', 'distinguishedName']
##    retrieveAttributes2 = ['eTUserid', 'eTFullName', 'eTGlobalUserName', 'eTFirstName', 'eTLastName']

##    Filter = "(&(objectClass=user)(objectcategory=person)(sAMAccountName=%s))"
##    Filter3 = "(&(objectClass=group)(sAMAccountName=%s))"
##    Filter2 = "(&(objectClass=eTGlobalUser)(eTGlobalUserName=%s))"

def init_ldaps(username, password, server, port=636, DEBUG=False):
    """initiates a ldaps connection
    @rtype : ldap.ldapobject.LDAPObject
    """
    if DEBUG:
        warning('trying to connect to %s:%d as %s\n\tcertfile:%s\n'%(server, port, username, data.certfile))
    ldapurl = "ldaps://%s:%d"%(server, port)

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, data.certfile)
    if DEBUG:
        ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        ldapmodule_trace_level = 1
    else:
        ldapmodule_trace_level = 0
    ldapmodule_trace_file = sys.stderr
    l = ldap.initialize(ldapurl, trace_level=ldapmodule_trace_level, trace_file=ldapmodule_trace_file)
    l.set_option(ldap.OPT_REFERRALS, 0)
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    l.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    if DEBUG:
        l.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
    l.set_option(ldap.OPT_X_TLS_CACERTFILE, data.certfile)
    l.bind_s(username, password, ldap.AUTH_SIMPLE)
    
    return l


def init_ldap(username, password, server, port=389, DEBUG=False):
    """initiates a ldap connection
    @rtype : ldap.ldapobject.LDAPObject
    """
    if DEBUG:
        warning('trying to connect to %s:%d as %s\n'%(server, port, username))
    ldapurl = "ldap://%s:%d"%(server, port)

    if DEBUG:
        ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
        ldapmodule_trace_level = 1
    else:
        ldapmodule_trace_level = 0
    ldapmodule_trace_file = sys.stderr
    l = ldap.initialize(ldapurl, trace_level=ldapmodule_trace_level, trace_file=ldapmodule_trace_file)
    l.set_option(ldap.OPT_REFERRALS, 0)
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

    if DEBUG:
        l.set_option( ldap.OPT_DEBUG_LEVEL, 255 )
    l.bind_s(username, password, ldap.AUTH_SIMPLE)
    
    return l


def search_ldap(l, filter, base, scope=ldap.SCOPE_SUBTREE, attributes=None, accountname=None, DEBUG=False):
    """queries a ldap server and returns the list of results
    @rtype : dict
    """
    if '%s' in filter:
        query = filter % accountname
    else:
        query = filter
    if DEBUG:
        warning("searching for user '%s' in base: %s. retrieve attributes: %s, scope: %s"%(accountname, base, attributes, scope))
        warning('Filter string: %s'%(query,))
    try:
        ldap_result_id = l.search(base, scope, query, attributes)
        if DEBUG:
            warning('ldap_result_id: %s'%ldap_result_id)
        result_set = llist()
        result_type, result_data = l.result(ldap_result_id, 0)
        if DEBUG:
            warning('len of result_data: %d'%len(result_data))
        while result_type == ldap.RES_SEARCH_ENTRY:
            result_data = result_data[0]
            #data = ( result_data[0] , { i:result_data[1][i]  for i in result_data[1] } )
            user_data = ldict({i: result_data[1][i][0] if len(result_data[1][i])==1 else result_data[1][i] for i in result_data[1]})
            user_data['dn'] = result_data[0]
            if isinstance(user_data['dn'], list):
                user_data['dn'] = user_data['dn'][0]

            result_set.append(user_data)
            result_type, result_data = l.result(ldap_result_id, 0)
            if DEBUG:
                warning('len of result_data: %d'%len(result_data))

        return result_set

    except ldap.LDAPError, e:
        print e
        return None



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
            t_p = path(t_list.name)
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
    group = parser.add_mutually_exclusive_group(required=True)
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
            data.file = path(getstr('enter csv filename, or drag the file here: '))
        else:
            data.file = path(cmd.file)
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

def add_ldap_object(l, filter, objectname, nametemplate, objecttype, base, attributes, scope=ldap.SCOPE_SUBTREE, DEBUG=False):
    """adds a new object to a ldap server
    @rtype : string
    """
    try:
        assert not '*' in objectname
    except:
        e = ldap.INVALID_DN_SYNTAX('no wild cards is allowed in the object name')
        raise e
    obj_list = []
    try:
        obj_list = search_ldap(l, filter, objectname, base, attributes=attributes.keys())
    except:
        pass
    finally:
        if obj_list and len(obj_list):
            e = ldap.ALREADY_EXISTS('object exists %s' % obj_list[0][nametemplate])
            raise e

    try:
##        dn = template % (objectname)
        dn = '%s=%s,%s' % (nametemplate, objectname, base)
        attrs = {}
        attrs['objectclass'] = objecttype
        for k in attributes:
            attrs[k] = attributes[k]
        ldif = modlist.addModlist(attrs)
        print dn
        print ldif
        l.add_s(dn, ldif)
    except ldap.LDAPError, e:
        print e
        return None
    except Exception as e:
        return None

	
def login_ps():
    """
    logs in to the Provisioning Server and returns the LDAP object.
    @return: LDAPObject
    """
    try:
        assert data.user is not None
        assert data.passwd is not None
        assert not '*' in data.user
        assert not '@' in data.user
    except:
        raise 'login information not set or are incorrect'

    try:
        print data.dc
        l = init_ldap(data.userTemplate % data.user, data.passwd, data.dc, data.port)
        login = (
            search_ldap(l, data.userFilter % data.user, data.baseDN,
                        attributes=['eTGlobalUserName'])
                    )[0]
    except Exception as e:
        error("Provisioning server access denied or Global user doesn't exists")
        raise e

    warning('%s logged in to the Provisioning Server' % login['eTGlobalUserName'])
    l.__enter__ = lambda: l
    l.__exit__ = lambda x,y,z: l.unbind_s()
    return l
    
def login_active():
    """
    logs in to the Active Directory and returns LDAP objects.
    @return: LDAPObject
    """
    try:
        assert data.user is not None
        assert data.passwd is not None
        assert not '*' in data.user
        assert not '@' in data.user
    except:
        raise 'login information not set or are incorrect'

    try:
        print data.dc2
        l = init_ldap(data.user + data.usersuffix, data.passwd, data.dc2)
        login = (
            search_ldap(l, data.userFilter2 % data.user, data.baseDN2,
                        attributes=['sAMAccountName'])
                    )[0]
    except Exception as e:
        error("Active Directory access denied or user doesn't exists")
        raise e

    warning('%s logged in to the Active Directory' % login['sAMAccountName'])
    
##    def __enter__():
##        return l
##    def __exit__():
##        l.unbind_s()
    l.__enter__ = lambda: l
    l.__exit__ = lambda x,y,z: l.unbind_s()
    return l

def read_csv(csv_file):
    """
    processes a csv file and returns lists of users.
    @param csv_file: file object for a csv file
    @return: list
    """
    reader = csv.DictReader(csv_file)
    if 'PERSON_ID' in reader.fieldnames:
        key = 'PERSON_ID'
    elif 'LogonName' in reader.fieldnames:
        key = 'LogonName'
    else:
        raise 'no username field specified in the file'
    user_list = []
    for item in reader:
        try:
            uid = item[key]
            assert uid
            user_list.append(uid)
        except:
            warning('empty username')
    if not user_list:
        raise 'empty list of users'
    return user_list


@automain
def main():
    login_ps()
    login_active()
    print '\r\nPress Enter to continute...'
    raw_input('')
