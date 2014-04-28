<?php

namespace ride\library\security\model;

/**
 * Chain of security models
 */
class ChainSecurityModel implements SecurityModel {

    /**
     * Models to wrap
     * @var array
     */
    protected $models = array();

    /**
     * Gets a string representation of this model
     * @return string
     */
    public function __toString() {
        $models = array();

        foreach ($this->models as $model) {
            if (method_exists($model, '__toString')) {
                $models[] = (string) $model;
            } else {
                $models[] = get_class($model);
            }
        }

        return '[' . implode(', ', $models) . ']';
    }

    /**
     * Adds a security model to the chain
     * @param SecurityModel $securityModel
     * @return null
     */
    public function addSecurityModel(ChainableSecurityModel $securityModel) {
        if ($securityModel->ping()) {
            $this->models[] = $securityModel;
        }
    }

    /**
     * Removes a security model from the chain
     * @param SecurityModel $securityModel
     * @return boolean
     */
    public function removeSecurityModel(ChainableSecurityModel $securityModel) {
        foreach ($this->models as $index => $model) {
            if ($model === $securityModel) {
                unset($models[$index]);

                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the security model is ready to work
     * @return boolean True if the model is ready, false otherwise
     */
    public function ping() {
        return $this->models ? true : false;
    }

    /**
     * Gets the paths which are secured for anonymous users
     * @return array Array with a path regular expression per element
     */
    public function getSecuredPaths() {
        $paths = array();

        foreach ($this->models as $model) {
            $modelPaths = $model->getSecuredPaths();

            foreach ($modelPaths as $path) {
                $paths[$path] = $path;
            }
        }

        return $paths;
    }

    /**
     * Sets the paths which are secured for anonymous users
     * @param array $routes Array with a path regular expression per element
     * @return null
     */
    public function setSecuredPaths(array $paths) {
        foreach ($this->models as $model) {
            $model->setSecuredPaths($paths);

            break;
        }
    }

    /**
     * Sets the granted permissions to a role
     * @param Role $role Role to set the permissions to
     * @param array $permissionCodes Array with a permission code per element
     * @return null
     */
    public function setGrantedPermissionsToRole(Role $role, array $permissionCodes) {
        foreach ($this->models as $model) {
            if ($model->ownsRole($role)) {
                $model->setGrantedPermissionsToRole($role, $permissionCodes);

                return;
            }
        }
    }

    /**
     * Sets the allowed paths to a role
     * @param Role $role Role to set the routes to
     * @param array $paths Array with a path regular expression per element
     * @return null
     */
    public function setAllowedPathsToRole(Role $role, array $paths) {
        foreach ($this->models as $model) {
            if ($model->ownsRole($role)) {
                $model->setAllowedPathsToRole($role, $paths);

                return;
            }
        }
    }

    /**
     * Saves the provided roles for the provided user
     * @param User $user User to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles) {
        foreach ($this->models as $model) {
            if ($model->ownsUser($user)) {
                $model->setRolesToUser($user, $roles);

                return;
            }
        }
    }

    /**
     * Gets a user by it's id
     * @param string $id Id of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserById($id) {
        foreach ($this->models as $model) {
            $user = $model->getUserById($id);
            if ($user) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByUsername($username) {
        foreach ($this->models as $model) {
            $user = $model->getUserByUsername($username);
            if ($user) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserByEmail($email) {
        foreach ($this->models as $model) {
            $user = $model->getUserByEmail($email);
            if ($user) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getUsers(array $options = null) {
        $users = array();

        foreach ($this->models as $model) {
            $modelUsers = $model->getUsers($options);

            foreach ($modelUsers as $user) {
                $users[] = $user;

                if (isset($options['limit']) && count($users) >= $options['limit']) {
                    break 2;
                }
            }
        }

        return $users;
    }

    /**
     * Counts the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     * </ul>
     * @return integer
     */
    public function countUsers(array $options = null) {
        $count = 0;

        foreach ($this->models as $model) {
            $count += $model->countUsers($options);
        }

        return $count;
    }

    /**
     * Creates a new user
     * @return User
     */
    public function createUser() {
        foreach ($this->models as $model) {
            return $model->createUser();
        }
    }

    /**
     * Saves a user to the model
     * @param User $user User to save
     * @return null
     */
    public function saveUser(User $user) {
        foreach ($this->models as $model) {
            if ($model->ownsUser($user)) {
                $model->saveUser($user);

                return;
            }
        }
    }

    /**
     * Deletes the provided user
     * @param User $user User to delete
     * @return null
     */
    public function deleteUser(User $user) {
        foreach ($this->models as $model) {
            if ($model->ownsUser($user)) {
                $model->deleteUser($user);

                return;
            }
        }
    }

    /**
     * Gets a role by it's id
     * @param string $id Id of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleById($id) {
        foreach ($this->models as $model) {
            $role = $model->getRoleById($id);
            if ($role) {
                return $role;
            }
        }

        return null;
    }

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleByName($name) {
        foreach ($this->models as $model) {
            $role = $model->getRoleByName($name);
            if ($role) {
                return $role;
            }
        }

        return null;
    }

    /**
     * Gets all the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>name</li>
     *     <li>query</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getRoles(array $options = null) {
        $roles = array();

        foreach ($this->models as $model) {
            $modelRoles = $model->getRoles($options);

            foreach ($modelRoles as $role) {
                $roles[] = $role;

                if (isset($options['limit']) && count($roles) >= $options['limit']) {
                    break 2;
                }
            }
        }

        return $roles;
    }

    /**
     * Counts the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     * </ul>
     * @return integer
     */
    public function countRoles(array $options = null) {
        $count = 0;

        foreach ($this->models as $model) {
            $count += $model->countRoles($options);
        }

        return $count;
    }

    /**
     * Creates a new role
     * @return Role
     */
    public function createRole() {
        foreach ($this->models as $model) {
            return $model->createRole();
        }
    }

    /**
     * Saves a role to the model
     * @param Role $role Role to save
     * @return null
     */
    public function saveRole(Role $role) {
        foreach ($this->models as $model) {
            if ($model->ownsRole($role)) {
                $model->saveRole($role);

                return;
            }
        }
    }

    /**
     * Deletes a role from the model
     * @param Role $role
     * @return null
     */
    public function deleteRole(Role $role) {
        foreach ($this->models as $model) {
            if ($model->ownsRole($role)) {
                $model->deleteRole($role);

                return;
            }
        }
    }

    /**
     * Gets all the permissions
     * @return array Array with Permission objects
     */
    public function getPermissions() {
        $permissions = array();

        foreach ($this->models as $model) {
            $modelPermissions = $model->getPermissions();

            foreach ($modelPermissions as $permission) {
                $permissions[$permission->getCode()] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Checks whether a given permission is available
     * @param string $code Code of the permission to check
     * @return boolean
     */
    public function hasPermission($code) {
        foreach ($this->models as $model) {
            if ($model->hasPermission($code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Registers a new permission to the model
     * @param string $code Code of the permission
     * @return null
     */
    public function addPermission($code) {
        foreach ($this->models as $model) {
            $model->addPermission($code);

            return;
        }
    }

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function deletePermission($code) {
        foreach ($this->models as $model) {
            $model->deletePermission($code);
        }
    }

}
