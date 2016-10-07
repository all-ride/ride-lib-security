<?php

namespace ride\library\security\authenticator;

use ride\library\http\Request;
use ride\library\security\exception\UsernameAuthenticationException;
use ride\library\security\exception\UnauthorizedException;
use ride\library\security\exception\UserNotFoundException;
use ride\library\security\exception\UserSwitchException;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Abstract helper implementation of a Authenticator
 */
abstract class AbstractAuthenticator implements Authenticator {

    /**
     * Instance of the security manager
     * @var \ride\library\security\SecurityManager
     */
    protected $securityManager;

    /**
     * Instance of the current user
     * @var \ride\library\security\model\User
     */
    protected $user = false;

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $manager Instance of the
     * security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $manager = null) {
        $this->securityManager = $manager;
    }

    /**
     * Gets the security manager of the authenticator
     * @return \ride\library\security\SecurityManager The security manager
     */
    public function getSecurityManager() {
        return $this->securityManager;
    }

    /**
     * Authenticates a user through the incoming request
     * @param \ride\library\http\Request $request
     * @return \ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request) {
        return null;
    }

    /**
     * Login a user
     * @param string $username Provided username
     * @param string $password Provided password
     * @return \ride\library\security\model\User The user if the login succeeded
     * @throws \ride\library\security\exception\AuthenticationException when the
     * user could not be authenticated
     */
    public function login($username, $password) {
        throw new UsernameAuthenticationException();
    }

    /**
     * Logout the current user. If the current user is a switched user, the
     * original user is now again the current user
     * @return null
     */
    public function logout() {
        $this->user = false;

        return null;
    }

    /**
     * Gets the current user
     * @return \ride\library\security\model\User|null The current user if logged
     * in, null otherwise
     */
    public function getUser() {
        return $this->user;
    }

    /**
     * Sets the current authenticated user
     * @param \ride\library\security\model\User $user User to set the
     * authentication status for
     * @return User updated user with the information of the authentification
     */
    public function setUser(User $user = null) {
        if ($user === null) {
            $this->user = false;

            return null;
        }

        $this->user = $user;

        return $this->user;
    }

    /**
     * Switch to the provided user to test it's permissions. When logging out,
     * the user before switching will again be the current user
     * @param string $username The username of the user to switch to
     * @return boolean
     * @throws \ride\library\security\exception\UnauthorizedException when not
     * authenticated
     * @throws \ride\library\security\exception\UserNotFoundException when the
     * requested user could not be found
     */
    public function switchUser($username) {
        return false;
    }

    /**
     * Checks is the current user is a switched user
     * @return boolean
     */
    public function isSwitchedUser() {
        return false;
    }

    /**
     * Gets and checks the user the switch to
     * @param string username
     * @return \ride\library\security\model\User
     * @throws \ride\library\security\exception\UnauthorizedException when not
     * authenticated or allowed
     * @throws \ride\library\security\exception\UserNotFoundException when the
     * user does not exist
     */
    protected function getUserForSwitch($username) {
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

        return $switchedUser;
    }

}
