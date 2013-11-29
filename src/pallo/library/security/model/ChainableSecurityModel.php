<?php

namespace pallo\library\security\model;

/**
 * Model of the security data
 */
interface ChainableSecurityModel extends SecurityModel {

    /**
     * Checks if this model owns the provided user instance
     * @param User $user
     * @return boolean
     */
    public function ownsUser(User $user);

    /**
     * Checks if this model owns the provided role instance
     * @param Role $role
     * @return boolean
     */
    public function ownsRole(Role $role);

    /**
     * Checks if this model owns the provided permission instance
     * @param Permission $permission
     * @return boolean
     */
    public function ownsPermission(Permission $permission);

}