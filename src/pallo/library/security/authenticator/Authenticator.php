<?php

namespace pallo\library\security\authenticator;

use pallo\library\http\Request;
use pallo\library\security\model\User;
use pallo\library\security\SecurityManager;

/**
 * Interface to maintain the authentication of a user
 */
interface Authenticator {

    /**
     * Sets the security manager to the authenticator
     * @param pallo\library\security\SecurityManager $manager Instance of the
     * security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $manager = null);

    /**
     * Gets the security manager of the authenticator
     * @return pallo\library\security\SecurityManager $manager Instance of the
     * security manager
     */
    public function getSecurityManager();

    /**
     * Authenticates a user through the incoming request
     * @param pallo\library\http\Request $request
     * @return pallo\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request);

    /**
     * Login a user
     * @param string $username Provided username
     * @param string $password Provided password
     * @return pallo\library\security\model\User The user if the login succeeded
     * @throws pallo\library\security\exception\AuthenticationException when the
     * user could not be authenticated
     */
    public function login($username, $password);

    /**
     * Logout the current user. If the current user is a switched user, the
     * original user is now again the current user
     * @return null
     */
    public function logout();

    /**
     * Gets the current user
     * @return pallo\library\security\model\User|null The current user if logged
     * in, null otherwise
     */
    public function getUser();

    /**
     * Sets the current authenticated user
     * @param pallo\library\security\model\User $user User to set the
     * authentication status for
     * @return User updated user with the information of the authentification
     */
    public function setUser(User $user);

    /**
     * Switch to the provided user to test it's permissions. When logging out,
     * the user before switching will again be the current user
     * @param string $username The username of the user to switch to
     * @return null
     * @throws pallo\library\security\exception\UnauthorizedException when not
     * authenticated
     * @throws pallo\library\security\exception\UserNotFoundException when the
     * requested user could not be found
     */
    public function switchUser($username);

}