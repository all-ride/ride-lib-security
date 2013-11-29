<?php

namespace pallo\library\security;

use pallo\library\encryption\hash\Hash;
use pallo\library\event\EventManager;
use pallo\library\http\Request;
use pallo\library\log\Log;
use pallo\library\security\authenticator\Authenticator;
use pallo\library\security\exception\PathMatcherNotSetException;
use pallo\library\security\exception\SecurityModelNotSetException;
use pallo\library\security\exception\SecurityException;
use pallo\library\security\matcher\PathMatcher;
use pallo\library\security\model\Role;
use pallo\library\security\model\SecurityModel;
use pallo\library\security\model\User;

/**
 * Facade to the security system
 */
class SecurityManager {

    /**
     * Name of the event run after a login
     * @var string
     */
    const EVENT_LOGIN = 'security.authentication.login';

    /**
     * Event run when a user updates it's password. The event has the user
     * instance and the plain password as arguments.
     * @var string
     */
    const EVENT_PASSWORD_UPDATE = 'security.password.update';

    /**
     * Source for the log messages
     * @var string
     */
    const LOG_SOURCE = 'security';

    /**
     * Name of the username field
     * @var string
     */
    const USERNAME = 'username';

    /**
     * Name of the password field
     * @var unknown_type
     */
    const PASSWORD = 'password';

    /**
     * Permission to switch user
     * @var string
     */
    const PERMISSION_SWITCH = 'security.switch';

    /**
     * Authenticator which is being used
     * @var pallo\library\security\authenticator\Authenticator
     */
    private $authenticator;

    /**
     * Instance of the event manager
     * @var pallo\library\event\EventManager
     */
    private $eventManager;

    /**
     * Instance of the Log
     * @var pallo\library\log\Log
     */
    private $log;

    /**
     * Security model which is being used
     * @var pallo\library\security\model\SecurityModel
     */
    private $model;

    /**
     * Hash algorithm for passwords
     * @var pallo\library\encryption\hash\Hash
     */
    private $hashAlgorithm;

    /**
     * Matcher for a path against path regular expressions
     * @var pallo\library\security\matcher\PathMatcher
     */
    private $pathMatcher;

    /**
     * Incoming request to authenticate the user
     * @var pallo\library\http\Request
     */
    private $request;

    /**
     * Flag to see if the authenticate method has been invoken on the
     * authenticator
     * @var boolean
     */
    private $isAuthenticated;

    /**
     * Constructs a new security manager
     * @param pallo\core\Zibo $pallo Instance of Zibo to trigger events
     * @param pallo\library\security\authenticator\Authenticator $authenticator
     * @return null
     */
    public function __construct(Authenticator $authenticator, EventManager $eventManager) {
        $this->setAuthenticator($authenticator);

        $this->eventManager = $eventManager;
        $this->log = null;
        $this->pathMatcher = null;
        $this->request = null;
    }

    /**
     * Sets the instance of the Log
     * @param pallo\library\log\Log $log
     * @return null
     */
    public function setLog(Log $log) {
        $this->log = $log;
    }

    /**
     * Sets the hash algorithm
     * @param pallo\library\encryption\hash\Hash $hashAlgorithm Hash
     * implementation
     * @return null
     */
    public function setHashAlgorithm(Hash $hashAlgorithm = null) {
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Hashes the provided password
     * @param string $password Plain text password
     * @return string Hashed password
     */
    public function hashPassword($password) {
        if ($this->hashAlgorithm === null) {
            return $password;
        }

        return $this->hashAlgorithm->hash($password);
    }

    /**
     * Sets the authenticator
     * @param pallo\library\security\authenticator\Authenticator $authenticator
     * @return null
     */
    public function setAuthenticator(Authenticator $authenticator) {
        $this->authenticator = $authenticator;
        $this->authenticator->setSecurityManager($this);

        $this->isAuthenticated = false;
    }

    /**
     * Gets the authenticator which is currently in use
     * @return pallo\library\security\authenticator\Authenticator
     */
    public function getAuthenticator() {
        return $this->authenticator;
    }

    /**
     * Sets the security model
     * @param pallo\library\security\model\SecurityModel $model Security model to use
     * @return null
     */
    public function setSecurityModel(SecurityModel $model = null) {
        if ($model) {
            if (method_exists($model, '__toString')) {
                $modelString = (string) $model;
            } else {
                $modelString = get_class($model);
            }

            if (!$model->ping()) {
                if ($this->log) {
                    $this->log->logDebug('Security model ' . $modelString . ' provided but not ready for work', null, self::LOG_SOURCE);
                }

                $model = null;
            } elseif ($this->log) {
                $this->log->logDebug('Using security model', $modelString, self::LOG_SOURCE);
            }
        } elseif ($this->log) {
            if ($this->model) {
                if (method_exists($this->model, '__toString')) {
                    $modelString = (string) $this->model;
                } else {
                    $modelString = get_class($this->model);
                }
            } else {
                $modelString = null;
            }

            $this->log->logDebug('Unsetting security model', $modelString, self::LOG_SOURCE);
        }

        $this->model = $model;
    }

    /**
     * Gets the security model which is currently in use
     * @param boolean $throwException Set to true to throw an exception when no security model has been set
     * @return pallo\library\security\model\SecurityModel|null
     * @throws pallo\library\security\exception\SecurityModelNotSetException when $throwException is set to true and no security model has been set
     */
    public function getSecurityModel($throwException = true) {
        if ($throwException && !$this->model) {
            throw new SecurityModelNotSetException();
        }

        return $this->model;
    }

    /**
     * Sets the path matcher
     * @param pallo\library\security\matcher\\PathMatcher $pathMatcher
     * @return null
     */
    public function setPathMatcher(PathMatcher $pathMatcher) {
        $this->pathMatcher = $pathMatcher;
    }

    /**
     * Gets the path matcher
     * @return pallo\library\security\matcher\PathMatcher|null
     */
    public function getPathMatcher() {
        if (!$this->pathMatcher) {
            throw new PathMatcherNotSetException();
        }

        return $this->pathMatcher;
    }

    /**
     * Sets the incoming request to make it available to the authenticator
     * @param pallo\library\http\Request $request
     * @return null
     */
    public function setRequest(Request $request) {
        $this->request = $request;
    }

    /**
     * Gets the current user
     * @return pallo\library\security\model\User Current user if authenticated,
     * null otherwise
     */
    public function getUser() {
        if (!$this->model) {
            return null;
        }

        $user = $this->authenticator->getUser();

        if ($user || $this->isAuthenticated || !$this->request) {
            return $user;
        }

        $this->isAuthenticated = true;

        return $this->authenticator->authenticate($this->request);
    }

    /**
     * Sets the current user
     * @param pallo\library\security\model\User $user Current user
     * @return null
     */
    public function setUser(User $user) {
        $this->authenticator->setUser($user);
    }

    /**
     * Switch the current user
     * @param string $username Username to switch
     * @return null
     * @throws pallo\library\security\exception\UnauthorizedException when not authenticated
     * @throws pallo\library\security\exception\UserNotFoundException when the requested user could not be found
     */
    public function switchUser($username) {
        $this->authenticator->switchUser($username);
    }

    /**
     * Login a user
     * @param string $username The provided username
     * @param string $password The provided password
     * @return pallo\library\security\model\User|null The user if the login
     * succeeded, null otherwise
     * @throws pallo\library\security\exception\AuthenticationException when
     * the user could not be authenticated
     * @throws pallo\library\security\exception\SecurityModelNotSetException
     * when no security model has been set
     */
    public function login($username, $password) {
        $user = $this->authenticator->login($username, $password);

        $this->eventManager->triggerEvent(self::EVENT_LOGIN, array('user' => $user));

        return $user;
    }

    /**
     * Logout the current user
     * @return null
     * @throws pallo\library\security\exception\SecurityModelNotSetException
     * when no security model has been set
     */
    public function logout() {
        $this->authenticator->logout();
    }

    /**
     * Checks whether the current user is granted the provided permission
     * @param string $code Code of the permission
     * @return boolean True if granted, false otherwise
     * @throws pallo\library\security\exception\SecurityModelNotSetException
     * when no security model has been set
     */
    public function isPermissionGranted($code) {
        if (!$this->model) {
            if ($this->log) {
                $this->log->logDebug('Permission ' . $code . ' is granted', 'no security model set', self::LOG_SOURCE);
            }

            return true;
        }

        if (!$this->model->hasPermission($code)) {
            $this->model->registerPermission($code);
        }

        $user = $this->getUser();

        if ($user === null) {
            if ($this->log) {
                $this->log->logDebug('Permission ' . $code . ' denied', 'not authenticated', self::LOG_SOURCE);
            }

            return false;
        }

        if ($user->isSuperUser() || $user->isPermissionGranted($code)) {
            if ($this->log) {
                $this->log->logDebug('Permission ' . $code . ' granted', 'user ' . $user->getUsername(), self::LOG_SOURCE);
            }

            return true;
        }

        if ($this->log) {
            $this->log->logDebug('Permission ' . $code . ' denied', '', self::LOG_SOURCE);
        }

        return false;
    }

    /**
     * Checks whether the current user is allowed to view the provided path
     * @param string $path Path to check
     * @return boolean
     */
    public function isPathAllowed($path) {
        if (!$this->model) {
            if ($this->log) {
                $this->log->logDebug('Path ' . $path . ' allowed', 'no security model set', self::LOG_SOURCE);
            }

            return true;
        }

        $allowed = !$this->pathMatcher->matchPath($path, $this->model->getSecuredPaths());
        if ($allowed) {
            if ($this->log) {
                $this->log->logDebug('Path ' . $path . ' allowed', 'path is not secured', self::LOG_SOURCE);
            }

            return true;
        }

        $user = $this->getUser();
        if ($user != null) {
            if ($user->isSuperUser() || $user->isPathAllowed($path, $this->pathMatcher)) {
                if ($this->log) {
                    $this->log->logDebug('Path ' . $path . ' is allowed', 'allowed for user ' . $user->getUserName(), self::LOG_SOURCE);
                }

                return true;
            } elseif ($this->log) {
                $this->log->logDebug('Path ' . $path . ' is denied', 'no clearance', self::LOG_SOURCE);
            }
        } elseif ($this->log) {
            $this->log->logDebug('Path ' . $path . ' is denied', 'not authenticated', self::LOG_SOURCE);
        }

        return false;
    }

}