<?php

namespace pallo\library\security\authenticator;

use pallo\library\security\authenticator\io\AuthenticatorIO;
use pallo\library\security\authenticator\AbstractAuthenticator;
use pallo\library\security\exception\InactiveAuthenticationException;
use pallo\library\security\exception\PasswordAuthenticationException;
use pallo\library\security\exception\UnauthorizededException;
use pallo\library\security\exception\UsernameAuthenticationException;
use pallo\library\security\exception\UserNotFoundException;
use pallo\library\security\exception\UserSwitchException;
use pallo\library\security\exception\SecurityException;
use pallo\library\security\exception\UnauthorizedException;
use pallo\library\security\model\User;
use pallo\library\security\SecurityManager;

/**
 * Authenticator with user storage in a cookie
 */
class GenericAuthenticator extends AbstractAuthenticator {

    /**
     * Default authentication timeout
     * @var integer
     */
    const DEFAULT_TIMEOUT = 1800; // half hour

    /**
     * Default flag for unique authentication
     * @var boolean
     */
    const DEFAULT_UNIQUE = false;

    /**
     * Name of the user preference for the authentication token
     * @var string
     */
    const PREFERENCE_TOKEN = 'security.token';

    /**
     * Name of the user preference for the authentication timeout
     * @var string
     */
    const PREFERENCE_TIMEOUT = 'security.timeout';

    /**
     * Session name for the authentication string
     * @var string
     */
    const VAR_AUTHENTICATION_STRING = 'security.authentication';

    /**
     * Session name for the switched user name
     * @var string
     */
    const VAR_SWITCHED_USERNAME = 'security.username.switched';

    /**
     * Session name for the user name
     * @var string
     */
    const VAR_USERNAME = 'security.username';

    /**
     * The salt for the identification token
     * @var string
     */
    private $salt;

    /**
     * Flag to see
     * @var boolean
     */
    private $isUnique;

    /**
     * The timeout of the authentication in seconds
     * @var integer
     */
    private $timeout;

    /**
     * Constructs a new authenticator.
     * @param string $salt The security salt
     * @param integer $timeout Authentication timeout in seconds
     * @param boolean $isUnique Set to true to allow only 1 client at the same
     * time for a user, this is more secure but does not always react as
     * expected
     * @return null
     */
    public function __construct(AuthenticatorIO $io, $salt, $timeout = null, $isUnique = null) {
        if ($timeout === null) {
            $timeout = self::DEFAULT_TIMEOUT;
        }

        if ($isUnique === null) {
            $isUnique = self::DEFAULT_UNIQUE;
        }

        $this->io = $io;
        $this->user = false;

        $this->setSalt($salt);
        $this->setTimeout($timeout);
        $this->setIsUnique($isUnique);
    }

    /**
     * Login a user
     * @param string $username
     * @param string $password
     * @return pallo\library\security\model\User User instance if login succeeded
     * @throws pallo\library\security\exception\AuthenticationException when the
     * login failed
     */
    public function login($username, $password) {
        $user = $this->securityManager->getSecurityModel()->getUserByUsername($username);
        if ($user === null) {
            $this->logout();

            throw new UsernameAuthenticationException();
        }

        if (!$user->isActive()) {
            $this->logout();

            throw new InactiveAuthenticationException();
        }

        if ($this->securityManager->hashPassword($password) != $user->getPassword()) {
            $this->logout();

            throw new PasswordAuthenticationException();
        }

        return $this->setUser($user);
    }

    /**
     * Logout the current user
     * @return null
     */
    public function logout() {
        $this->user = false;

        $this->io->set(self::VAR_AUTHENTICATION_STRING, null);
        $this->io->set(self::VAR_SWITCHED_USERNAME, null);
        $this->io->set(self::VAR_USERNAME, null);
    }

    /**
     * Gets the current user.
     * @return pallo\library\security\model\User User instance if a user is
     * logged in, null otherwise
     * @throws pallo\library\security\exception\UnauthorizedException when a
     * user switch is set but not allowed
     */
    public function getUser() {
        if ($this->user !== false) {
            return $this->user;
        }

        $this->user = null;

        $username = $this->io->get(self::VAR_USERNAME);
        if (!$username) {
            return null;
        }

        $securityModel = $this->securityManager->getSecurityModel();

        $user = $securityModel->getUserByUsername($username);
        if (!$user) {
            return null;
        }

        if (!$this->isUnique()) {
            $identifier = $this->getIdentifier($user->getUserName());
            if ($identifier != $this->io->get(self::VAR_AUTHENTICATION_STRING)) {
                return null;
            }
        } elseif (!$this->isUniqueAuthentication($user)) {
            return null;
        }

        $user = $this->setUser($user);

        $username = $this->io->get(self::VAR_SWITCHED_USERNAME);
        if (!$username) {
            return $user;
        }

        $switchedUser = $securityModel->getUserByUsername($username);
        if (!$switchedUser) {
            return $user;
        }

        if (!$user->isSuperUser() && !$user->isPermissionGranted(SecurityManager::PERMISSION_SWITCH)) {
            $this->io->set(self::VAR_SWITCHED_USERNAME, null);

            throw new UnauthorizedException('Could not switch user: not allowed');
        }

        $this->user = $switchedUser;

        return $switchedUser;
    }

    /**
     * Sets the current authenticated user
     * @param pallo\library\security\model\User $user User to set the
     * authentication for
     * @return User updated user with the information of the authentification
     */
    public function setUser(User $user) {
        $username = $user->getUserName();
        $identifier = $this->getIdentifier($username);

        if (!$this->isUnique()) {
            $this->io->set(self::VAR_USERNAME, $username);
            $this->io->set(self::VAR_AUTHENTICATION_STRING, $identifier);
            $this->user = $user;

            return $this->user;
        }

        $now = time();

        $token = $this->generateToken();
        $timeout = $now + $this->getTimeout();

        $authenticationString = $identifier . ':' . $token;
        $this->io->set(self::VAR_USERNAME, $username);
        $this->io->set(self::VAR_AUTHENTICATION_STRING, $authenticationString);

        $user->setUserPreference(self::PREFERENCE_TOKEN, $token);
        $user->setUserPreference(self::PREFERENCE_TIMEOUT, $timeout);

        $securityModel = $this->securityManager->getSecurityModel();
        $securityModel->saveUser($user);

        $this->user = $user;

        return $this->user;
    }

    /**
     * Switch to the provided user to test it's permissions. When logging out,
     * the user before switching will be the current user
     * @param string $username The username of the user to switch to
     * @return null
     * @throws pallo\library\security\exception\UnauthorizedException when not
     * authenticated or not allowed to switch
     * @throws pallo\library\security\exception\UserNotFoundException when the
     * requested user could not be found
     */
    public function switchUser($username) {
        $user = $this->getUser();
        if (!$user) {
            throw new UnauthorizedException('Could not switch user: not authenticated');
        }

        if (!$user->isSuperUser() && !$user->isPermissionGranted(SecurityManager::PERMISSION_SWITCH)) {
            throw new UnauthorizedException('Could not switch user: not allowed');
        }

        $switchedUser = $this->securityManager->getSecurityModel()->getUserByUsername($username);
        if (!$switchedUser) {
            throw new UserNotFoundException('Could not switch user: user not found');
        }

        if (!$user->isSuperUser() && $switchedUser->isSuperUser()) {
            throw new UserSwitchException('Could not switch user: ' . $switchedUser->getUserName() . ' is a super user .');
        }

        $this->user = $switchedUser;
        $this->io->set(self::VAR_SWITCHED_USERNAME, $username);
    }

    /**
     * Checks if the provided user is uniquely authenticated
     * @param pallo\library\security\model\User $user
     * @return boolean True If the authentication is unique, false otherwise
     */
    protected function isUniqueAuthentication(User $user) {
        $string = $this->io->get(self::VAR_AUTHENTICATION_STRING);
        if (!$string || strpos($string, ':') === false) {
            return false;
        }

        list($identifier, $token) = explode(':', $string);
        if (!(ctype_alnum($identifier) && ctype_alnum($token))) {
            return false;
        }

        $userToken = $user->getPreference(self::PREFERENCE_TOKEN);
        $userTimeout = $user->getPreference(self::PREFERENCE_TIMEOUT);
        $userIdentifier = $this->getIdentifier($user->getUserName());
        $now = time();

        if (!($userToken == $token && $userTimeout > $now && $userIdentifier == $identifier)) {
            return false;
        }

        return true;
    }

    /**
     * Gets the identifier for a given value
     * @param string $value Value to get an identifier from
     * @return string Identifier of the value
     */
    protected function getIdentifier($value) {
        return md5($this->salt . md5($value . $this->salt));
    }

    /**
     * Generates a random token
     * @return string
     */
    protected function generateToken() {
        return md5(uniqid(rand(), true));
    }

    /**
     * Sets the salt which is used to create a identifier
     * @param string salt
     * @return null
     * @throws pallo\library\security\exception\SecurityException when an
     * invalid salt is provided
     */
    public function setSalt($salt) {
        if (!is_string($salt) || $salt == '') {
            throw new SecurityException('Provided salt is empty');
        }

        $this->salt = $salt;
    }

    /**
     * Gets the salt which is used to create a identifier
     * @return string
     */
    public function getSalt() {
        return $this->salt;
    }

    /**
     * Sets the timeout of the authentification
     * @param integer $timeout Timeout in seconds
     * @return null
     * @throws pallo\library\security\exception\SecurityException when the
     * provided timeout is invalid
     */
    public function setTimeout($timeout) {
        if (!is_numeric($timeout) || $timeout < 0) {
            throw new SecurityException('Provided timeout is invalid');
        }

        $this->timeout = (integer) $timeout;
    }

    /**
     * Gets the timeout of the authentification
     * @return integer Timeout in seconds
     */
    public function getTimeout() {
        return $this->timeout;
    }

    /**
     * Sets the unique flag
     * @param boolean $flag True to let a user authenticate only at one client
     * at a time, false otherwise
     * @return null
     */
    public function setIsUnique($flag) {
        $this->isUnique = $flag;
    }

    /**
     * Gets the unique flag
     * @return boolean True to let a user authenticate only at one client at a
     * time, false otherwise
     */
    public function isUnique() {
        return $this->isUnique;
    }

}