<?php

namespace ride\library\security\voter;

use ride\library\security\SecurityManager;

/**
 * Abstract implementation of a security voter
 */
abstract class AbstractVoter implements Voter {

    /**
     * Instance of the security manager
     * @var \ride\library\security\SecurityManager
     */
    protected $securityManager;

    /**
     * Sets the security manager to the authenticator
     * @param \ride\library\security\SecurityManager $securityManager Instance 
     * of the security manager
     * @return null
     */
    public function setSecurityManager(SecurityManager $securityManager = null) {
        $this->securityManager = $securityManager;
    }

    /**
     * Gets the security manager of the authenticator
     * @return \ride\library\security\SecurityManager $manager Instance of the
     * security manager
     */
    public function getSecurityManager() {
        return $this->securityManager;
    }

}