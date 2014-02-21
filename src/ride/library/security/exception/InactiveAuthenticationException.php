<?php

namespace ride\library\security\exception;

use ride\library\security\SecurityManager;

/**
 * Inactive user exception
 */
class InactiveAuthenticationException extends AuthenticationException {

    /**
     * Message for the exception
     * @var string
     */
    const ERROR = 'Your account is not activated';

    /**
     * Translation key for the message
     * @var string
     */
    const TRANSLATION_ERROR = 'security.error.authentication.inactive';

    /**
     * Constructs a new exception
     * @return null
     */
    public function __construct() {
        parent::__construct(self::ERROR, self::TRANSLATION_ERROR, SecurityManager::USERNAME);
    }

}