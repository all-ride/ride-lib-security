<?php

namespace ride\library\security\authenticator;

use ride\library\http\Request;
use ride\library\security\exception\SecurityException;
use ride\library\security\exception\UsernameAuthenticationException;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Authenticator to chain multiple authenticators together
 */
class ChainAuthenticator extends AbstractAuthenticator {

    /**
     * Constructs a new chained authenticator
     * @return null
     */
    public function __construct() {
        $this->authenticators = array();
        $this->user = false;
    }

    /**
     * Adds a authenticator to the chain
     * @param Authenticator $authenticator
     * @return null
     */
    public function addAuthenticator(Authenticator $authenticator) {
        $this->authenticators[] = $authenticator;
    }

    /**
     * Gets all the authenticators of the chain
     * @return array
     */
    public function getAuthenticators() {
        return $this->authenticators;
    }

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $manager Instance of the
     * security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $manager = null) {
        foreach ($this->authenticators as $authenticator) {
            $authenticator->setSecurityManager($manager);
        }
    }

    /**
     * Authenticates a user through the incoming request
     * @param \ride\library\http\Request $request
     * @return \ride\library\security\model\User|null User if the authentication
     * succeeded
     */
    public function authenticate(Request $request) {
        foreach ($this->authenticators as $authenticator) {
            $user = $authenticator->authenticate($request);
            if ($user) {
                $this->user = $user;

                return $this->user;
            }
        }

        return parent::authenticate($request);
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
        foreach ($this->authenticators as $authenticator) {
            try {
                $this->user = $authenticator->login($username, $password);

                return $this->user;
            } catch (UsernameAuthenticationException $e) {

            }
        }

        return parent::login($username, $password);
    }

    /**
     * Logout the current user. If the current user is a switched user, the
     * original user is now again the current user
     * @return null
     */
    public function logout() {
        foreach ($this->authenticators as $authenticator) {
            $authenticator->logout($authenticator);
        }

        parent::logout();
    }

    /**
     * Gets the current user
     * @return \ride\library\security\model\User|null The current user if logged
     * in, null otherwise
     */
    public function getUser() {
        if ($this->user !== false) {
            return $this->user;
        }

        foreach ($this->authenticators as $authenticator) {
            $user = $authenticator->getUser();
            if ($user) {
                $this->user = $user;

                break;
            }
        }

        if (!$this->user) {
            $this->user = null;
        }

        return $this->user;
    }

    /**
     * Sets the current authenticated user
     * @param \ride\library\security\model\User $user User to set the
     * authentication status for
     * @return User updated user with the information of the authentification
     */
    public function setUser(User $user) {
        foreach ($this->authenticators as $authenticator) {
            $user = $authenticator->setUser($user);

            break;
        }

        return parent::setUser($user);
    }

    /**
     * Switch to the provided user to test it's permissions. When logging out,
     * the user before switching will again be the current user
     * @param string $username The username of the user to switch to
     * @return null
     * @throws \ride\library\security\exception\UnauthorizedException when not
     * authenticated
     * @throws \ride\library\security\exception\UserNotFoundException when the
     * requested user could not be found
     */
    public function switchUser($username) {
        foreach ($this->authenticators as $authenticator) {
            try {
                $authenticator->switchUser($username);
                $this->user = $authenticator->getUser();
            } catch (SecurityException $e) {

            }
        }
    }

}
