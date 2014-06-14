<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * MySQLi authentication backend
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Lech Groblewicz <kontakt@znpd.pl>
 * @author     Andreas Gohr <andi@splitbrain.org>
 * @author     Chris Smith <chris@jalakai.co.uk>
 * @author     Matthias Grimm <matthias.grimmm@sourceforge.net>
 * @author     Jan Schumann <js@schumann-it.com>
 */
class auth_plugin_authmysqli extends DokuWiki_Auth_Plugin {
    /** @var mysqli holds the database connection */
    protected $dbcon = null;
    /** @var int database version*/
    protected $dbver = 0;
    /** @var int database revision */
    protected $dbrev = 0;
    /** @var int database subrevision */
    protected $dbsub = 0;

    /**
     * Constructor
     *
     * checks if the mysqli interface is available, otherwise it will
     * set the variable $success of the basis class to false
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    public function __construct() {
        parent::__construct();

        if(!function_exists('mysqli_connect')) {
            $this->_debug("MySQLi err: PHP MySQLi extension not found.", -1, __LINE__, __FILE__);
            $this->success = false;
            return;
        }

        // set capabilities based upon config strings set
        if(!$this->getConf('server') || !$this->getConf('user') || !$this->getConf('database')) {
            $this->_debug("MySQLi err: insufficient configuration.", -1, __LINE__, __FILE__);

            $this->success = false;
            return;
        }

        $this->cando['addUser']   = $this->_chkcnf(
            array(
                 'getUserInfo',
                 'getGroups',
                 'addUser',
                 'getUserID',
                 'getGroupID',
                 'addGroup',
                 'addUserGroup'
            )
        );
        $this->cando['delUser']   = $this->_chkcnf(
            array(
                 'getUserID',
                 'delUser',
                 'delUserRefs'
            )
        );
        $this->cando['modLogin']  = $this->_chkcnf(
            array(
                 'getUserID',
                 'updateUser',
                 'UpdateTarget'
            )
        );
        $this->cando['modPass']   = $this->cando['modLogin'];
        $this->cando['modName']   = $this->cando['modLogin'];
        $this->cando['modMail']   = $this->cando['modLogin'];
        $this->cando['modGroups'] = $this->_chkcnf(
            array(
                 'getUserID',
                 'getGroups',
                 'getGroupID',
                 'addGroup',
                 'addUserGroup',
                 'delGroup',
                 'getGroupID',
                 'delUserGroup'
            )
        );
        /* getGroups is not yet supported
           $this->cando['getGroups']    = $this->_chkcnf(array('getGroups',
           'getGroupID')); */
        $this->cando['getUsers']     = $this->_chkcnf(
            array(
                 'getUsers',
                 'getUserInfo',
                 'getGroups'
            )
        );
        $this->cando['getUserCount'] = $this->_chkcnf(array('getUsers'));

        if($this->getConf('debug') >= 2) {
            $candoDebug = '';
            foreach($this->cando as $cd => $value) {
                if($value) { $value = 'yes'; } else { $value = 'no'; }
                $candoDebug .= $cd . ": " . $value . " | ";
            }
            $this->_debug("authmysqli cando: " . $candoDebug, 0, __LINE__, __FILE__);
        }
    }

    /**
     * Check if the given config strings are set
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     * @author  Lech Groblewicz <kontakt@znpd.pl>
     * @param   array $keys
     * @return  bool
     */
    protected function _chkcnf($keys) {
        foreach($keys as $key) {
            if(!$this->getConf($key)) return false;
        }

        return true;
    }

    /**
     * Checks if the given user exists and the given plaintext password
     * is correct. Furtheron it might be checked wether the user is
     * member of the right group
     *
     * Depending on which SQL string is defined in the config, password
     * checking is done here (getpass) or by the database (passcheck)
     *
     * @param  string $user user who would like access
     * @param  string $pass user's clear text password to check
     * @return bool
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    public function checkPass($user, $pass) {
        global $conf;
        $rc = false;

        if($this->_openDB()) {
            $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('checkPass'));
            $sql    = str_replace('%{pass}', $this->_escape($pass), $sql);
            $sql    = str_replace('%{dgroup}', $this->_escape($conf['defaultgroup']), $sql);
            $result = $this->_queryDB($sql);

            if($result !== false && count($result) == 1) {
                if($this->getConf('forwardClearPass') == 1)
                    $rc = true;
                else
                    $rc = auth_verifyPassword($pass, $result[0]['pass']);
            }
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Return user info
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $user user login to get data for
     * @return array|bool
     */
    public function getUserData($user) {
        if($this->_openDB()) {
            $this->_lockTables();
            $info = $this->_getUserInfo($user);
            $this->_unlockTables();
            $this->_closeDB();
        } else
            $info = false;
        return $info;
    }

    /**
     * Create a new User. Returns false if the user already exists,
     * null when an error occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $user  nick of the user
     * @param string $pwd   clear text password
     * @param string $name  full name of the user
     * @param string $mail  email address
     * @param array  $grps  array of groups the user should become member of
     * @return bool|null
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
        global $conf;

        if($this->_openDB()) {
            if(($info = $this->_getUserInfo($user)) !== false)
                return false; // user already exists

            // set defaultgroup if no groups were given
            if($grps == null)
                $grps = array($conf['defaultgroup']);

            $this->_lockTables();
            $pwd = $this->getConf('forwardClearPass') ? $pwd : auth_cryptPassword($pwd);
            $rc  = $this->_addUser($user, $pwd, $name, $mail, $grps);
            $this->_unlockTables();
            $this->_closeDB();
            if($rc) return true;
        }
        return null; // return error
    }

    /**
     * Modify user data
     *
     * An existing user dataset will be modified. Changes are given in an array.
     *
     * The dataset update will be rejected if the user name should be changed
     * to an already existing one.
     *
     * The password must be provides unencrypted. Pasword cryption is done
     * automatically if configured.
     *
     * If one or more groups could't be updated, an error would be set. In
     * this case the dataset might already be changed and we can't rollback
     * the changes. Transactions would be really usefull here.
     *
     * modifyUser() may be called without SQL statements defined that are
     * needed to change group membership (for example if only the user profile
     * should be modified). In this case we asure that we don't touch groups
     * even $changes['grps'] is set by mistake.
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool   true on success, false on error
     */
    public function modifyUser($user, $changes) {
        $rc = false;

        if(!is_array($changes) || !count($changes))
            return true; // nothing to change

        if($this->_openDB()) {
            $this->_lockTables();

            if(($uid = $this->_getUserID($user))) {
                $rc = $this->_updateUserInfo($changes, $uid);

                if($rc && isset($changes['grps']) && $this->cando['modGroups']) {
                    $groups = $this->_getGroups($user);
                    $grpadd = array_diff($changes['grps'], $groups);
                    $grpdel = array_diff($groups, $changes['grps']);

                    foreach($grpadd as $group)
                        if(($this->_addUserToGroup($user, $group, 1)) == false)
                            $rc = false;

                    foreach($grpdel as $group)
                        if(($this->_delUserFromGroup($user, $group)) == false)
                            $rc = false;
                }
            }

            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * [public function]
     *
     * Remove one or more users from the list of registered users
     *
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    function deleteUsers($users) {
        $count = 0;

        if($this->_openDB()) {
            if(is_array($users) && count($users)) {
                $this->_lockTables();
                foreach($users as $user) {
                    if($this->_delUser($user))
                        $count++;
                }
                $this->_unlockTables();
            }
            $this->_closeDB();
        }
        return $count;
    }

    /**
     * Counts users which meet certain $filter criteria.
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  array $filter  filter criteria in item/pattern pairs
     * @return int count of found users
     */
    public function getUserCount($filter = array()) {
        $rc = 0;

        if($this->_openDB()) {
            $sql = $this->_createSQLFilter($this->getConf('getUsers'), $filter);

            if($this->dbver >= 4) {
                $sql = substr($sql, 6); /* remove 'SELECT' or 'select' */
                $sql = "SELECT SQL_CALC_FOUND_ROWS".$sql." LIMIT 1";
                $this->_queryDB($sql);
                $result = $this->_queryDB("SELECT FOUND_ROWS()");
                $rc     = $result[0]['FOUND_ROWS()'];
            } else if(($result = $this->_queryDB($sql)))
                $rc = count($result);

            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Bulk retrieval of user data
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  int          $first  index of first user to be returned
     * @param  int          $limit  max number of users to be returned
     * @param  array|string $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($first = 0, $limit = 0, $filter = array()) {
        $out = array();

        if($this->_openDB()) {
            $this->_lockTables();
            $sql = $this->_createSQLFilter($this->getConf('getUsers'), $filter);
            $sql .= " ".$this->getConf('SortOrder');
            if($limit) {
                $sql .= " LIMIT $first, $limit";
            } elseif($first) {
                $sql .= " LIMIT $first";
            }
            $result = $this->_queryDB($sql);

            if(!empty($result)) {
                foreach($result as $user)
                    if(($info = $this->_getUserInfo($user['user'])))
                        $out[$user['user']] = $info;
            }

            $this->_unlockTables();
            $this->_closeDB();
        }
        return $out;
    }

    /**
     * Give user membership of a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user
     * @param   string $group
     * @return  bool   true on success, false on error
     */
    protected function joinGroup($user, $group) {
        $rc = false;

        if($this->_openDB()) {
            $this->_lockTables();
            $rc = $this->_addUserToGroup($user, $group);
            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Remove user from a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user  user that leaves a group
     * @param   string $group group to leave
     * @return  bool
     */
    protected function leaveGroup($user, $group) {
        $rc = false;

        if($this->_openDB()) {
            $this->_lockTables();
            $rc  = $this->_delUserFromGroup($user, $group);
            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * MySQLi is case-insensitive
     */
    public function isCaseSensitive() {
        return false;
    }

    /**
     * Adds a user to a group.
     *
     * If $force is set to true non existing groups would be created.
     *
     * The database connection must already be established. Otherwise
     * this function does nothing and returns 'false'. It is strongly
     * recommended to call this function only after all participating
     * tables (group and usergroup) have been locked.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user    user to add to a group
     * @param   string $group   name of the group
     * @param   bool   $force   create missing groups
     * @return  bool   true on success, false on error
     */
    protected function _addUserToGroup($user, $group, $force = false) {
        $newgroup = 0;

        if(($this->dbcon) && ($user)) {
            $gid = $this->_getGroupID($group);
            if(!$gid) {
                if($force) { // create missing groups
                    $sql      = str_replace('%{group}', $this->_escape($group), $this->getConf('addGroup'));
                    $gid      = $this->_modifyDB($sql);
                    $newgroup = 1; // group newly created
                }
                if(!$gid) return false; // group didn't exist and can't be created
            }

            $sql = $this->getConf('addUserGroup');
            if(strpos($sql, '%{uid}') !== false) {
                $uid = $this->_getUserID($user);
                $sql = str_replace('%{uid}', $this->_escape($uid), $sql);
            }
            $sql = str_replace('%{user}', $this->_escape($user), $sql);
            $sql = str_replace('%{gid}', $this->_escape($gid), $sql);
            $sql = str_replace('%{group}', $this->_escape($group), $sql);
            if($this->_modifyDB($sql) !== false) return true;

            if($newgroup) { // remove previously created group on error
                $sql = str_replace('%{gid}', $this->_escape($gid), $this->getConf('delGroup'));
                $sql = str_replace('%{group}', $this->_escape($group), $sql);
                $this->_modifyDB($sql);
            }
        }
        return false;
    }

    /**
     * Remove user from a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user  user that leaves a group
     * @param   string $group group to leave
     * @return  bool   true on success, false on error
     */
    protected function _delUserFromGroup($user, $group) {
        $rc = false;

        if(($this->dbcon) && ($user)) {
            $sql = $this->getConf('delUserGroup');
            if(strpos($sql, '%{uid}') !== false) {
                $uid = $this->_getUserID($user);
                $sql = str_replace('%{uid}', $this->_escape($uid), $sql);
            }
            $gid = $this->_getGroupID($group);
            if($gid) {
                $sql = str_replace('%{user}', $this->_escape($user), $sql);
                $sql = str_replace('%{gid}', $this->_escape($gid), $sql);
                $sql = str_replace('%{group}', $this->_escape($group), $sql);
                $rc  = $this->_modifyDB($sql) == 0 ? true : false;
            }
        }
        return $rc;
    }

    /**
     * Retrieves a list of groups the user is a member off.
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose groups should be listed
     * @return bool|array false on error, all groups on success
     */
    protected function _getGroups($user) {
        $groups = array();

        if($this->dbcon) {
            $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('getGroups'));
            $result = $this->_queryDB($sql);

            if($result !== false && count($result)) {
                foreach($result as $row)
                    $groups[] = $row['group'];
            }
            return $groups;
        }
        return false;
    }

    /**
     * Retrieves the user id of a given user name
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose id is desired
     * @return mixed  user id
     */
    protected function _getUserID($user) {
        if($this->dbcon) {
            $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('getUserID'));
            $result = $this->_queryDB($sql);
            return $result === false ? false : $result[0]['id'];
        }
        return false;
    }

    /**
     * Adds a new User to the database.
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user  login of the user
     * @param  string $pwd   encrypted password
     * @param  string $name  full name of the user
     * @param  string $mail  email address
     * @param  array  $grps  array of groups the user should become member of
     * @return bool
     */
    protected function _addUser($user, $pwd, $name, $mail, $grps) {
        if($this->dbcon && is_array($grps)) {
            $sql = str_replace('%{user}', $this->_escape($user), $this->getConf('addUser'));
            $sql = str_replace('%{pass}', $this->_escape($pwd), $sql);
            $sql = str_replace('%{name}', $this->_escape($name), $sql);
            $sql = str_replace('%{email}', $this->_escape($mail), $sql);
            $uid = $this->_modifyDB($sql);
            $gid = false;
            $group = '';

            if($uid) {
                foreach($grps as $group) {
                    $gid = $this->_addUserToGroup($user, $group, 1);
                    if($gid === false) break;
                }

                if($gid !== false){
                    return true;
                } else {
                    $this->_rollback();
                    $this->_debug("MySQLi err: Adding user '$user' to group '$group' failed.", -1, __LINE__, __FILE__);
                }
            }
        }
        return false;
    }

    /**
     * Deletes a given user and all his group references.
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose id is desired
     * @return bool
     */
    protected function _delUser($user) {
        if($this->dbcon) {
            $uid = $this->_getUserID($user);
            if($uid) {
                $sql = str_replace('%{uid}', $this->_escape($uid), $this->getConf('delUserRefs'));
                $this->_modifyDB($sql);
                $sql = str_replace('%{uid}', $this->_escape($uid), $this->getConf('delUser'));
                $sql = str_replace('%{user}', $this->_escape($user), $sql);
                $this->_modifyDB($sql);
                return true;
            }
        }
        return false;
    }

    /**
     * getUserInfo
     *
     * Gets the data for a specific user The database connection
     * must already be established for this function to work.
     * Otherwise it will return 'false'.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user  user's nick to get data for
     * @return bool|array false on error, user info on success
     */
    protected function _getUserInfo($user) {
        $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('getUserInfo'));
        $result = $this->_queryDB($sql);
        if($result !== false && count($result)) {
            $info         = $result[0];
            $info['grps'] = $this->_getGroups($user);
            return $info;
        }
        return false;
    }

    /**
     * Updates the user info in the database
     *
     * Update a user data structure in the database according changes
     * given in an array. The user name can only be changes if it didn't
     * exists already. If the new user name exists the update procedure
     * will be aborted. The database keeps unchanged.
     *
     * The database connection has already to be established for this
     * function to work. Otherwise it will return 'false'.
     *
     * The password will be crypted if necessary.
     *
     * @param  array $changes  array of items to change as pairs of item and value
     * @param  mixed $uid      user id of dataset to change, must be unique in DB
     * @return bool true on success or false on error
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    protected function _updateUserInfo($changes, $uid) {
        $sql = $this->getConf('updateUser')." ";
        $cnt = 0;
        $err = 0;

        if($this->dbcon) {
            foreach($changes as $item => $value) {
                if($item == 'user') {
                    if(($this->_getUserID($changes['user']))) {
                        $err = 1; /* new username already exists */
                        break; /* abort update */
                    }
                    if($cnt++ > 0) $sql .= ", ";
                    $sql .= str_replace('%{user}', $value, $this->getConf('UpdateLogin'));
                } else if($item == 'name') {
                    if($cnt++ > 0) $sql .= ", ";
                    $sql .= str_replace('%{name}', $value, $this->getConf('UpdateName'));
                } else if($item == 'pass') {
                    if(!$this->getConf('forwardClearPass'))
                        $value = auth_cryptPassword($value);
                    if($cnt++ > 0) $sql .= ", ";
                    $sql .= str_replace('%{pass}', $value, $this->getConf('UpdatePass'));
                } else if($item == 'mail') {
                    if($cnt++ > 0) $sql .= ", ";
                    $sql .= str_replace('%{email}', $value, $this->getConf('UpdateEmail'));
                }
            }

            if($err == 0) {
                if($cnt > 0) {
                    $sql .= " ".str_replace('%{uid}', $uid, $this->getConf('UpdateTarget'));
                    if(get_class($this) == 'auth_mysqli') $sql .= " LIMIT 1"; //some PgSQL inheritance comp.
                    $this->_modifyDB($sql);
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieves the group id of a given group name
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $group   group name which id is desired
     * @return mixed group id
     */
    protected function _getGroupID($group) {
        if($this->dbcon) {
            $sql    = str_replace('%{group}', $this->_escape($group), $this->getConf('getGroupID'));
            $result = $this->_queryDB($sql);
            return $result === false ? false : $result[0]['id'];
        }
        return false;
    }

    /**
     * Opens a connection to a database and saves the handle for further
     * usage in the object. The successful call to this functions is
     * essential for most functions in this object.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @return bool
     */
    protected function _openDB() {
        if(!$this->dbcon) {
            $con = @mysqli_connect($this->getConf('server'), $this->getConf('user'), $this->getConf('password'));
            if($con) {
                if((mysqli_select_db($con, $this->getConf('database')))) {
                    if((preg_match('/^(\d+)\.(\d+)\.(\d+).*/', mysqli_get_server_info($con), $result)) == 1) {
                        $this->dbver = $result[1];
                        $this->dbrev = $result[2];
                        $this->dbsub = $result[3];
                    }
                    $this->dbcon = $con;
                    if($this->getConf('charset')) {
                        mysqli_query($con, 'SET CHARACTER SET "'.$this->getConf('charset').'"');
                    }
                    return true; // connection and database successfully opened
                } else {
                    mysqli_close($con);
                    $this->_debug("MySQLi err: No access to database {$this->getConf('database')}.", -1, __LINE__, __FILE__);
                }
            } else {
                $this->_debug(
                    "MySQLi err: Connection to {$this->getConf('user')}@{$this->getConf('server')} not possible.",
                    -1, __LINE__, __FILE__
                );
            }

            return false; // connection failed
        }
        return true; // connection already open
    }

    /**
     * Closes a database connection.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    protected function _closeDB() {
        if($this->dbcon) {
            mysqli_close($this->dbcon);
            $this->dbcon = null;
        }
    }

    /**
     * Sends a SQL query to the database and transforms the result into
     * an associative array.
     *
     * This function is only able to handle queries that returns a
     * table such as SELECT.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $query  SQL string that contains the query
     * @return array with the result table
     */
    protected function _queryDB($query) {
        if($this->getConf('debug') >= 2) {
            msg('MySQLi query: '.hsc($query), 0, __LINE__, __FILE__);
        }

        $resultarray = array();
        if($this->dbcon) {
            $result = @mysqli_query($this->dbcon, $query);
            if($result) {
                while(($t = mysqli_fetch_assoc($result)) !== null)
                    $resultarray[] = $t;
                mysqli_free_result($result);
                return $resultarray;
            }
            $this->_debug('MySQLi err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
        }
        return false;
    }

    /**
     * Sends a SQL query to the database
     *
     * This function is only able to handle queries that returns
     * either nothing or an id value such as INPUT, DELETE, UPDATE, etc.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $query  SQL string that contains the query
     * @return int|bool insert id or 0, false on error
     */
    protected function _modifyDB($query) {
        if($this->getConf('debug') >= 2) {
            msg('MySQLi query: '.hsc($query), 0, __LINE__, __FILE__);
        }

        if($this->dbcon) {
            $result = @mysqli_query($this->dbcon, $query);
            if($result) {
                $rc = mysqli_insert_id($this->dbcon); //give back ID on insert
                if($rc !== false) return $rc;
            }
            $this->_debug('MySQLi err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
        }
        return false;
    }

    /**
     * mysqli does not support mysql v3, so we could rely on autocommit functionality (remember to use INNODB engine!)
     * @author Lech Groblewicz <kontakt@znpd.pl>
     *
     * @param $autocommit bool Whether enable autocommit or not.
     * @return bool
     */
    protected function _lockTables($autocommit = false) {
        if($this->dbcon) {
            return mysqli_autocommit($this->dbcon, $autocommit);
        }
        return false;
    }

    /**
     * Rollback the transaction.
     *
     * @author Lech Groblewicz <kontakt@znpd.pl>
     * @return bool
     */
    protected function _rollback() {
        if ($this->dbcon) {
            return mysqli_rollback($this->dbcon);
        }
        return false;
    }


    /**
     * Commit the data from the transaction / enable autocommit.
     *
     * @author Lech Groblewicz <kontakt@znpd.pl>
     * @return bool
     */
    protected function _unlockTables() {
        return $this->_lockTables(true);
    }

    /**
     * Transforms the filter settings in an filter string for a SQL database
     * The database connection must already be established, otherwise the
     * original SQL string without filter criteria will be returned.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $sql     SQL string to which the $filter criteria should be added
     * @param  array $filter  array of filter criteria as pairs of item and pattern
     * @return string SQL string with attached $filter criteria on success, original SQL string on error
     */
    protected function _createSQLFilter($sql, $filter) {
        $SQLfilter = "";
        $cnt       = 0;

        if($this->dbcon) {
            foreach($filter as $item => $pattern) {
                $tmp = '%'.$this->_escape($pattern).'%';
                if($item == 'user') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{user}', $tmp, $this->getConf('FilterLogin'));
                } else if($item == 'name') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{name}', $tmp, $this->getConf('FilterName'));
                } else if($item == 'mail') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{email}', $tmp, $this->getConf('FilterEmail'));
                } else if($item == 'grps') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{group}', $tmp, $this->getConf('FilterGroup'));
                }
            }

            // we have to check SQLfilter here and must not use $cnt because if
            // any of cnf['Filter????'] is not defined, a malformed SQL string
            // would be generated.

            if(strlen($SQLfilter)) {
                $glue = strpos(strtolower($sql), "where") ? " AND " : " WHERE ";
                $sql  = $sql.$glue.$SQLfilter;
            }
        }

        return $sql;
    }

    /**
     * Escape a string for insertion into the database
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     *
     * @param  string  $string The string to escape
     * @param  boolean $like   Escape wildcard chars as well?
     * @return string
     */
    protected function _escape($string, $like = false) {
        if($this->dbcon) {
            $string = mysqli_real_escape_string($this->dbcon, $string);
        } else {
            $string = addslashes($string);
        }
        if($like) {
            $string = addcslashes($string, '%_');
        }
        return $string;
    }

    /**
     * Wrapper around msg() but outputs only when debug is enabled
     *
     * @param string $message
     * @param int    $err
     * @param int    $line
     * @param string $file
     * @return void
     */
    protected function _debug($message, $err, $line, $file) {
        if(!$this->getConf('debug')) return;
        msg($message, $err, $line, $file);
    }
}
