<?php

namespace ride\library\security\voter;

use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Interface to implement your security layer through custom voters
 */
interface Voter {

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $manager Instance of the
     * security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $manager = null);

    /**
     * Checks if the provided permission is granted for the provided user
     * @param string $permission Code of the permission to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isGranted($permission, User $user = null);

    /**
     * Checks if the provided path is allowed for the provided user
     * @param string $path Path to check
     * @param \ride\library\security\model\User $user User to check
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isAllowed($path, User $user = null);

}