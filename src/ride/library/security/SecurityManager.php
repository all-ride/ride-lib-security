<?php

namespace ride\library\security;

use ride\library\encryption\hash\Hash;
use ride\library\event\EventManager;
use ride\library\http\Request;
use ride\library\log\Log;
use ride\library\security\authenticator\Authenticator;
use ride\library\security\exception\PathMatcherNotSetException;
use ride\library\security\exception\SecurityModelNotSetException;
use ride\library\security\exception\SecurityException;
use ride\library\security\matcher\PathMatcher;
use ride\library\security\model\SecurityModel;
use ride\library\security\model\User;

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
     * @var \ride\library\security\authenticator\Authenticator
     */
    protected $authenticator;

    /**
     * Instance of the event manager
     * @var \ride\library\event\EventManager
     */
    protected $eventManager;

    /**
     * Instance of the Log
     * @var \ride\library\log\Log
     */
    protected $log;

    /**
     * Security model which is being used
     * @var \ride\library\security\model\SecurityModel
     */
    protected $model;

    /**
     * Hash algorithm for passwords
     * @var \ride\library\encryption\hash\Hash
     */
    protected $hashAlgorithm;

    /**
     * Matcher for a path against path regular expressions
     * @var \ride\library\security\matcher\PathMatcher
     */
    protected $pathMatcher;

    /**
     * Incoming request to authenticate the user
     * @var \ride\library\http\Request
     */
    protected $request;

    /**
     * Flag to see if the authenticate method has been invoken on the
     * authenticator
     * @var boolean
     */
    protected $isAuthenticated;

    /**
     * Constructs a new security manager
     * @param \ride\library\system\system $ride Instance of Zibo to trigger events
     * @param \ride\library\security\authenticator\Authenticator $authenticator
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
     * @param \ride\library\log\Log $log
     * @return null
     */
    public function setLog(Log $log) {
        $this->log = $log;
    }

    /**
     * Sets the hash algorithm
     * @param \ride\library\encryption\hash\Hash $hashAlgorithm Hash
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
     * @param \ride\library\security\authenticator\Authenticator $authenticator
     * @return null
     */
    public function setAuthenticator(Authenticator $authenticator) {
        $this->authenticator = $authenticator;
        $this->authenticator->setSecurityManager($this);

        $this->isAuthenticated = false;
    }

    /**
     * Gets the authenticator which is currently in use
     * @return \ride\library\security\authenticator\Authenticator
     */
    public function getAuthenticator() {
        return $this->authenticator;
    }

    /**
     * Sets the security model
     * @param \ride\library\security\model\SecurityModel $model Security model to use
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
     * @return \ride\library\security\model\SecurityModel|null
     * @throws \ride\library\security\exception\SecurityModelNotSetException when $throwException is set to true and no security model has been set
     */
    public function getSecurityModel($throwException = true) {
        if ($throwException && !$this->model) {
            throw new SecurityModelNotSetException();
        }

        return $this->model;
    }

    /**
     * Sets the path matcher
     * @param ride\library\security\matcher\\PathMatcher $pathMatcher
     * @return null
     */
    public function setPathMatcher(PathMatcher $pathMatcher) {
        $this->pathMatcher = $pathMatcher;
    }

    /**
     * Gets the path matcher
     * @return \ride\library\security\matcher\PathMatcher|null
     */
    public function getPathMatcher() {
        if (!$this->pathMatcher) {
            throw new PathMatcherNotSetException();
        }

        return $this->pathMatcher;
    }

    /**
     * Sets the incoming request to make it available to the authenticator
     * @param \ride\library\http\Request $request
     * @return null
     */
    public function setRequest(Request $request) {
        $this->request = $request;
    }

    /**
     * Gets the current user
     * @return \ride\library\security\model\User Current user if authenticated,
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
     * @param \ride\library\security\model\User $user Current user
     * @return null
     */
    public function setUser(User $user = null) {
        $this->authenticator->setUser($user);
    }

    /**
     * Switch the current user
     * @param string $username Username to switch
     * @return null
     * @throws \ride\library\security\exception\UnauthorizedException when not authenticated
     * @throws \ride\library\security\exception\UserNotFoundException when the requested user could not be found
     */
    public function switchUser($username) {
        $this->authenticator->switchUser($username);
    }

    /**
     * Login a user
     * @param string $username The provided username
     * @param string $password The provided password
     * @return \ride\library\security\model\User|null The user if the login
     * succeeded, null otherwise
     * @throws \ride\library\security\exception\AuthenticationException when
     * the user could not be authenticated
     * @throws \ride\library\security\exception\SecurityModelNotSetException
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
     * @throws \ride\library\security\exception\SecurityModelNotSetException
     * when no security model has been set
     */
    public function logout() {
        $this->authenticator->logout();
    }

    /**
     * Checks whether the current user is granted the provided permission
     * @param string $code Code of the permission
     * @return boolean True if granted, false otherwise
     * @throws \ride\library\security\exception\SecurityModelNotSetException
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
            $this->model->addPermission($code);
        }

        try {
            $user = $this->getUser();
        } catch (SecurityException $exception) {
            $user = null;
        }

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

        try {
            $user = $this->getUser();
        } catch (SecurityException $exception) {
            $user = null;
        }

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

    /**
     * Checks whether the current user is allowed to view the provided URL
     * @param string $url URL to check
     * @return boolean
     */
    public function isUrlAllowed($url) {
        $path = parse_url($url, PHP_URL_PATH);
        if ($path === null) {
            throw new SecurityException('Could not check the permissions of a URL: provided URL is invalid');
        }

        return $this->isPathAllowed($path);
    }

}
