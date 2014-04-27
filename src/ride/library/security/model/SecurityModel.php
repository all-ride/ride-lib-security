<?php

namespace ride\library\security\model;

/**
 * Model of the security data
 */
interface SecurityModel {

    /**
     * Checks if the security model is ready to work
     * @return boolean True if the model is ready, false otherwise
     */
    public function ping();

    /**
     * Gets the paths which are secured for anonymous users
     * @return array Array with a path regular expression per element
     */
    public function getSecuredPaths();

    /**
     * Sets the paths which are secured for anonymous users
     * @param array $routes Array with a path regular expression per element
     * @return null
     */
    public function setSecuredPaths(array $paths);

    /**
     * Creates a new user
     * @return User
     */
    public function createUser();

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByUsername($username);

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByEmail($email);

    /**
     * Find the users which match the provided part of a username
     * @param string $query Part of a username to match
     * @return array Array with the usernames which match the provided query
     */
    public function findUsersByUsername($query);

    /**
     * Find the users which match the provided part of a email address
     * @param string $query Part of a email address
     * @return array Array with the usernames of the users which match the
     * provided query
     */
    public function findUsersByEmail($query);

    /**
     * Saves a user to the model
     * @param User $user User to save
     * @return null
     */
    public function saveUser(User $user);

    /**
     * Saves the provided roles for the provided user
     * @param User $user User to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles);

    /**
     * Deletes the provided user
     * @param User $user User to delete
     * @return null
     */
    public function deleteUser(User $user);

    /**
     * Creates a new role
     * @return Role
     */
    public function createRole();

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleByName($name);

    /**
     * Gets all the roles
     * @return array
     */
    public function getRoles();

    /**
     * Finds roles by it's name
     * @param string $query Part of the name
     * @return array Array with Role objects
     */
    public function findRolesByName($query);

    /**
     * Saves a role to the model
     * @param Role $role Role to save
     * @return null
     */
    public function saveRole(Role $role);

    /**
     * Sets the granted permissions to a role
     * @param Role $role Role to set the permissions to
     * @param array $permissionCodes Array with a permission code per element
     * @return null
     */
    public function setGrantedPermissionsToRole(Role $role, array $permissionCodes);

    /**
     * Sets the allowed paths to a role
     * @param Role $role Role to set the routes to
     * @param array $paths Array with a path regular expression per element
     * @return null
     */
    public function setAllowedPathsToRole(Role $role, array $paths);

    /**
     * Deletes a role from the model
     * @param Role $role
     * @return null
     */
    public function deleteRole(Role $role);

    /**
     * Gets all the permissions
     * @return array Array with Permission objects
     */
    public function getPermissions();

    /**
     * Checks whether a given permission is available
     * @param string $code Code of the permission to check
     * @return boolean
     */
    public function hasPermission($code);

    /**
     * Registers a new permission to the model
     * @param string $code Code of the permission
     * @return null
     */
    public function registerPermission($code);

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function unregisterPermission($code);

}
