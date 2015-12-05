'''
module LDAPHelper is a module to help you create correct LDAP queries and objects with a simple syntax.

object LDAPQuery: helps to create a simple easy-to-read ldap query
onject LDAPHelper: saves main required ldap attributes and provides mapping
object llist: enables creating lists that initialize from a filtered ldap result
object ldict: provides dictionaries with ability to exclude a parameter
object LDAP_DIFF: performs a DIFF on related ldap objects from different ldap schemas.

@changelist:
1.2: added additional EP accounts.
1.3: added temp attributes to PSUser.
'''
__author__ = 'Mohammad Kajbaf'
__version__ = 1.3
from kajlib import automain
import collections

class LDAPQuery(object):
    '''
    An LDAPQuery makes and handles creation of LDAP queries in a simple format.
    You can use string formats, dictionary formats or 
    '''
    _t_and  = '(&%s)'
    _t_or   = '(|%s)'
    _t_not  = '(!%s)'
    _t_query= '(%s=%s)'
    
    @staticmethod
    def join(queries):
        query_set = ''.join(queries)
        return query_set
    @staticmethod
    def make_set(query_dict):
        raise NotImplementedError
        return LDAPQuery._t_query % (attr, val)

    def __init__(self, query='', **kwargs):
        assert isinstance(query, basestring)
        query = query.strip()
        assert query == '' or (query.startswith('(') and query.endswith(')'))
        self._query = query
        if kwargs:
            if self._query:
                q_array = [self._query]
            else:
                q_array = []
            for i, j in kwargs.items():
                q_array.append( self.make(i, j) )
            if len(q_array) > 1:
                self._query = self._and( self.join(q_array))
            else:
                self._query = self.join(q_array)

    def make(self, attr, val):
        if isinstance(val, basestring):
            return self._t_query % (attr, val)
        return self._or(
            self.join([self.make(attr, v) for v in val])
            )
    def _and(self, q_array):
        return self._t_and % self.join(q_array)
    def _or(self, q_array):
        return self._t_or % self.join(q_array)
    def _not(self, q_array):
        return self._t_not % self.join(q_array)

    def __and__(self, other):
        if isinstance(other, basestring):
            other = other.strip()
            assert other.startswith('(') and other.endswith(')')
            if self._query:
                return LDAPQuery(
                    self._and( self.join( [self._query, other ] ))
                    )
            return LDAPQuery(other)
        if isinstance(other, dict):
            q_array = [self._query]
            for i,j in other.items():
                q_array.append( self.make(i, j) )
            return LDAPQuery(
                self._and (self.join(q_array))
                )
        if isinstance(other, LDAPQuery):
            return LDAPQuery(
                self._and (self._query + other._query)
                )
        raise NotImplementedError

    def __or__(self, other):
        if isinstance(other, basestring):
            other = other.strip()
            assert other.startswith('(') and other.endswith(')')
            if self._query:
                return LDAPQuery(
                    self._or( self.join( [self._query, other ] ))
                    )
            return LDAPQuery(other)
        if isinstance(other, dict):
            q_array = [self._query]
            for i,j in other.items():
                q_array.append( self.make(i, j) )
            return LDAPQuery(
                self._or (self.join(q_array))
                )
        if isinstance(other, LDAPQuery):
            return LDAPQuery(
                self._or (self._query + other._query)
                )
        raise NotImplementedError

    def __invert__(self):
        if self._query:
            return LDAPQuery(
                self._not (self._query)
                )
        return self
    def __repr__(self):
        return "LDAPQuery(r'%s')"%self._query
    def __str__(self):
        return self._query
    @property
    def string(self):
        return self.__str__()

class Helper:
    _class = 'objectClass'
    class PSUser:
        _root        = r'eTGlobalUserContainerName=Global Users,eTNamespaceName=CommonObjects,dc=im,dc=eta'
        objectClass = 'eTGlobalUser'
        dn          = 'dn'
        cn          = 'eTGlobalUserName'
        name        = 'eTGlobalUserName'
        id          =  'eTUserid'
        displayName = 'eTFullName'
        passwd      = 'eTPassword'
        city        = 'eTCity'
        company     = 'eTCompany'
        country     = 'eTCountry'
        department  = 'eTDepartment'
        description = 'eTDescription'
        first       = 'eTFirstName'
        last        = 'eTLastName'
        idm_state   = 'eTIMEnabledState'
        mobile      = 'eTMobilePhone'
        office      = 'eTOffice'
        role        = 'eTRoleDN'
        ps_state    = 'eTSuspended'
        title       = 'eTTitle'
        mail        = 'eTEmailAddress'
        mobile      = 'eTMobilePhone'
        ad_cn       = 'eTCustomField01'
        ad_id       = 'eTCustomField02'
        auto_ou     = 'eTCustomField03'
        his_change  = 'eTCustomField04'
        emp_id      = 'eTCustomField05'
        emp_type    = 'eTCustomField06'
        imp_flag    = 'eTCustomField07'
        iacc_flag   = 'eTCustomField08'
        iacc_state  = 'eTCustomField09'
        ad_dn       = 'eTCustomField10'
        manager     = 'eTCustomField11'
        fn_manager  = 'eTCustomField12'
        lastlogin   = 'eTCustomField15'
        his_policy  = 'eTCustomField20'
        ad_state    = 'eTCustomField50'
        temp_cn     = 'eTCustomField96'
        temp_fn     = 'eTCustomField97'
        temp_state  = 'eTCustomField98'
        temp_dn     = 'eTCustomField99'
    class PSTemplate:
        _root       = r'eTADSPolicyContainerName=Active Directory Policies,eTNamespaceName=CommonObjects,dc=im,dc=eta'
        objectClass = 'eTADSPolicy'
        dn          = 'dn'
        name        = 'eTADSPolicyName'
        groups      = 'eTADSmemberOf'
        endpoint    = 'eTAccountDirectory'
    class PSRole:
        _root       = r'eTRoleContainerName=Roles,eTNamespaceName=CommonObjects,dc=im,dc=eta'
        objectClass = 'eTRole'
        dn          = 'dn'
        name        = 'eTRoleName'
        groups      = 'eTADSmemberOf'
        endpoint    = 'eTAccountDirectory'
    class PSADSGroup:
        _root       = r'eTNamespaceName=ActiveDirectory,dc=im,dc=eta'
        objectClass = 'eTADSGroup'
        dn          = 'dn'
        name        = 'eTADSGroupName'
        ad_dn       = 'eTADSdistinguishedName'
        ad_object   = 'group'
        groups      = 'eTADSmemberOf'
        members     = 'eTADSmember'
        manager     = 'eTADSmanagedBy'
        group_type  = 'eTADSgroupType'
        email       = 'eTADSmail'
    class IFSAccount:
        _root       = r'eTNamespaceName=IFS2,dc=im,dc=eta'
        objectClass = 'eTDYNAccount'
        dn          = 'dn'
        name        = 'eTAccountName'
        displayName = 'eTDYN-str-multi-01'
        groups      = 'eTDYN-str-multi-08'
        IFS_state   = 'eTSuspended'
        endpoint    = 'eTDirectoryName'

    class ADUser:
        _root       = r'dc=ddddddd,dc=ir'
        objectClass = 'user'
        dn          = 'distinguishedName'
        cn          = 'name'
        name        = 'sAMAccountName'
        id          =  'userPrincipalName'
        displayName = 'displayName'
        first       = 'givenName'
        last        = 'sn'
        manager     = 'manager'
        groups      = 'memberOf'
        city        = 'l'
        company     = 'company'
        country     = 'co'
        department	= 'department'
        description	= 'description'
        state       = 'userAccountControl'
        mobile      = 'mobile'
        mail        = 'mail'


isstr = lambda s : isinstance(s, basestring)

'''
get a diff on ldap objects from different ldap skeletons based mapping
'''
class LDAP_DIFF(ldif.LDIFParser):
    _ignore_list = map(str.lower,
                       ['eTUpdate','eTCreate', 'eTDisable', 'eTEnable', 'eTDelete', 'eTID', 'eTPassword', 'eTRoleDN', 'eTSuspended', 'eTwf',
                        'eTAdminPwdChange', 'eTIMPassword', 'eTEff', #'eTCustomField04',
                        'eTUserDomain', 'eTADSwts', 'eTAccountDirectory',
                        ]
                       )
    _replace_list = map(str.lower,
                        ['eTConfigParamValue', 'eTConfigParamProperties']
                        )
    def ignore_attr(self, value):
        for i in self._ignore_list:
            if str.startswith(value.lower(), i):
                return True
        return False
    def config_attr(self, value):
        for i in self._replace_list:
            if str.startswith(value.lower(), i):
                return True
        return False

    def debug(self, msg, force=False):
        if self._debug or force:
            print msg
    
    def __init__(self, input, ldap_object, debug=False):
        ldif.LDIFParser.__init__(self, input)
        self._l = ldap_object
        self._ldif = []
        self._debug = debug

    def handle(self,dn,entry):
        data = {}
        self.debug('\rprocessing %s'%dn)
        if dn:
            try:
                c_values = self._l.search_s(dn,ldap.SCOPE_BASE)
            except:
                c_values = None
            if c_values:
                for c_dn, c_entry in c_values:
                    for e in entry:
                        if not self.ignore_attr(e):
                            if not e in c_entry:
                                data[e] = entry[e]
                            elif self.config_attr(e):
                                self.debug('config %s' %e)
                                if (isinstance(entry[e], str) and entry[e].lower() != c_entry[e].lower()) \
                                        or  (isinstance(entry[e], list) and entry[e][0].lower()!=c_entry[e][0].lower()):
                                    data[e] = entry[e]
                            else:
                                self.debug('exists: \t%s: %s'%(e, c_entry[e]))
                                if e.lower() == 'eTPolicyName'.lower():
                                    self.debug('ignoring Policy %s' %entry[e], True)
                    if data:
                        print 'dn: %s' % dn
                        for d in data:
                            print 'Adding:*** %s: %s'%(d, data[d])
##                        assert 'eTADSdisplayName' in data
                        self._ldif.append((dn, modlist.modifyModlist({}, data)))
            else:
                assert not c_values
                for e in entry:
                    if not self.ignore_attr(e):
                        data[e] = entry[e]
                    else:
                        if e.lower() == 'eTPolicyName'.lower():
                            self.debug('ignoring Policy %s' %entry[e], True)
                        else:
                            self.debug('ignore attrib: \t%s: %s'%(e, entry[e]))
                if data:
                    print 'dn: %s' % dn
                    for d in data:
                        print 'Adding:*** %s: %s'%(d, data[d])
                    self._ldif.append((dn, modlist.addModlist(data)))

    def parse(self):
        ldif.LDIFParser.parse(self)
        return self._ldif
    
    def update(self):
        for dn, entry in self._ldif:
            print 'updating: %s' % dn
            self._l.modify_s(dn, entry)


'''overload dict to provide subtract method
'''
class ldict(dict):
	def __sub__(self, other):
		'removes dict keys'
		if other and isinstance(other, collections.Iterable) and not isstr(other):
			for k in other:
				self.pop(k, 0)
		else:
			return dict.__sub__(self, other)
		return self

'''overload list to enable filtering 
'''
class llist(list):
	def filter(self, filter, action = None):
		self.__filter = filter
		self.__act = action
		_res = llist()
		for i in self:
			for k, v in filter.iteritems():
				_attr = i.get(k) 
				if not _attr:
					continue
				if _attr == v or isinstance(_attr, collections.Iterable) and v in _attr:
					_res.append(i)
					continue
		return _res                                                                              

@automain
def test():
    query1 = {'a':'1','b':'2'}
    q1 = LDAPQuery(**query1)
    print q1
