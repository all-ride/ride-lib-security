<?php

namespace ride\library\security\voter;

use ride\library\security\exception\SecurityException;
use ride\library\security\SecurityManager;

/**
 * Permission Interface to implement your security layer through custom voters
 */
class PermissionVoter implements Voter {
    
    /**
     * Checks if the provided permission is granted by the current user
     * @param string $permission Code of the permission to check
     * @param \ride\library\security\SecurityManager $securityManager Instance 
     * of the security manager
     * @return boolean|null True when granted, false when not granted or null 
     * when this voter has no opinion
     */
    public function isGranted($permission, SecurityManager $securityManager) {
        $securityModel = $securityManager->getSecurityModel();
        if (!$securityModel->hasPermission($code)) {
            $securityModel->addPermission($code);
        }

        try {
            $user = $securityManager->getUser();
        } catch (SecurityException $exception) {
            $user = null;
        }

        if ($user !== null && ($user->isSuperUser() || $user->isPermissionGranted($code))) {
            return true;
        }

        return false;
    }
    
}