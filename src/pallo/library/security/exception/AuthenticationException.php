<?php

namespace pallo\library\security\exception;

use pallo\library\security\SecurityManager;

/**
 * Basic authentication exception
 */
class AuthenticationException extends SecurityException {

    /**
     * Translation key for the error message
     * @var string
     */
    private $translationKey;

    /**
     * Name of the field which caused the error
     * @var string
     */
    private $field;

    /**
     * Construct this exception
     * @param string $error Error message
     * @param string $translationKey Translation key of the error message
     * @param string $field Name of the field which caused this exception (optional)
     * @return null
     */
    public function __construct($error, $translationKey, $field = null) {
        parent::__construct($error, 201);

        $this->setTranslationKey($translationKey);
        $this->setField($field);
    }

    /**
     * Sets the translation key of the error message
     * @param string $translationKey The translation key of the error message
     * @return null
     */
    private function setTranslationKey($translationKey) {
        $this->translationKey = $translationKey;
    }

    /**
     * Gets the translation key of the error message
     * @return string
     */
    public function getTranslationKey() {
        return $this->translationKey;
    }

    /**
     * Sets the name of the field that caused this exception
     * @param string $field name of the field
     * @return null
     * @throws pallo\ZiboException when the provided field name id not username, password or null
     */
    private function setField($field) {
        if ($field == null) {
            $this->field = null;
            return;
        }

        if ($field == SecurityManager::PASSWORD || $field == SecurityManager::USERNAME) {
            $this->field = $field;
            return;
        }

        throw new SecurityException('Could not set the field: invalid field provided, try username, password or null');
    }

    /**
     * Gets the name of the field that caused this exception
     * @return string
     */
    public function getField() {
        return $this->field;
    }

}