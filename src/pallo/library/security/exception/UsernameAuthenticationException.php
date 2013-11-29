<?php

namespace pallo\library\security\exception;

use pallo\library\security\SecurityManager;

/**
 * Incorrect username exception
 */
class UsernameAuthenticationException extends AuthenticationException {

    /**
     * Message for the exception
     * @var string
     */
    const ERROR = 'User does not exist';

    /**
     * Translation key for the error message
     * @var string
     */
    const TRANSLATION_ERROR = 'security.error.authentication.username';

    /**
     * Constructs a new exception
     * @return null
     */
    public function __construct() {
        parent::__construct(self::ERROR, self::TRANSLATION_ERROR, SecurityManager::USERNAME);
    }

}