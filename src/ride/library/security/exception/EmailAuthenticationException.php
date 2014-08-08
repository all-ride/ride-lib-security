<?php

namespace ride\library\security\exception;

use ride\library\security\SecurityManager;

/**
 * Email not confirmed exception
 */
class EmailAuthenticationException extends AuthenticationException {

    /**
     * Message for the exception
     * @var string
     */
    const ERROR = 'Email address is not confirmed';

    /**
     * Translation key for the error message
     * @var string
     */
    const TRANSLATION_ERROR = 'security.error.authentication.email';

    /**
     * Constructs a new exception
     * @return null
     */
    public function __construct() {
        parent::__construct(self::ERROR, self::TRANSLATION_ERROR, SecurityManager::USERNAME);
    }

}
