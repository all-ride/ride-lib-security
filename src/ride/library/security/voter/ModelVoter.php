<?php

namespace ride\library\security\voter;

use ride\library\security\matcher\PathMatcher;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Voter to check the security through the security model
 */
class ModelVoter extends AbstractVoter {

    /**
     * Matcher for a path against path regular expressions
     * @var \ride\library\security\matcher\PathMatcher
     */
    protected $pathMatcher;

    /**
     * Sets the path matcher
     * @param ride\library\security\matcher\\PathMatcher $pathMatcher
     * @return null
     */
    public function __construct(PathMatcher $pathMatcher) {
        $this->pathMatcher = $pathMatcher;
    }

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $securityManager Instance 
     * of the security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $securityManager = null) {
        $this->securityManager = $securityManager;

        if ($securityManager) {
            $this->securityModel = $securityManager->getSecurityModel(false);
        } else {
            $this->securityModel = null;
        }
    }

    /**
     * Checks if the provided permission is granted by the current user
     * @param string $permission Code of the permission to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isGranted($permission, User $user = null) {
        // make sure the permission exists
        if (!$this->securityModel->hasPermission($permission)) {
            $this->securityModel->addPermission($permission);
        }

        // check the permission
        if ($user !== null && ($user->isSuperUser() || $user->isPermissionGranted($permission))) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the provided path is allowed for the provided user
     * @param string $path Path to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isAllowed($path, User $user = null) {
        // check the path
        if (!$this->pathMatcher->matchPath($path, $this->securityModel->getSecuredPaths())) {
            return true;
        } elseif ($user !== null && ($user->isSuperUser() || $user->isPathAllowed($path, $this->pathMatcher))) {
            return true;
        }

        return false;
    } 
    
}