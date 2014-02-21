<?php

namespace ride\library\security\model;

/**
 * Permission of the SecurityModel
 */
interface Permission {

    /**
     * Gets the code of this permission
     * @return string
     */
    public function getCode();

    /**
     * Gets the description of this permission
     * @return string
     */
    public function getDescription();

}
