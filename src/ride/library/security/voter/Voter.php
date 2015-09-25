<?php

namespace ride\library\security\voter;

use ride\library\security\SecurityManager;

/**
 * Interface to implement your security layer through custom voters
 */
interface Voter {
    
    /**
     * Checks if the provided permission is granten by the provided user
     * @param string $permission Code of the permission to check
     * @param \ride\library\security\SecurityManager $securityManager Instance 
     * of the security manager
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isGranted($permission, SecurityManager $securityManager);
    
}