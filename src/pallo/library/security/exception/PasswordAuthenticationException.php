<?php

namespace pallo\library\security\exception;

use pallo\library\security\SecurityManager;

/**
 * Incorrect password exception
 */
class PasswordAuthenticationException extends AuthenticationException {

    /**
     * Error message of this exception
     * @var string
     */
    const ERROR = 'Password is incorrect';

    /**
     * Translation key for the error message
     * @var string
     */
    const TRANSLATION_ERROR = 'security.error.authentication.password';

    /**
     * Constructs a new password authentication exception
     * @return null
     */
    public function __construct() {
        parent::__construct(self::ERROR, self::TRANSLATION_ERROR, SecurityManager::PASSWORD);
    }

}