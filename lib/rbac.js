'use strict';

var Q = require('q');
var _ = require('lodash');

function RBAC(roles) {
    this.roles = roles;
}

/**
 * Verify that an operation is authorized for a given role.
 * @param  {Object} role A role object with a 'can' attribute containing
 * a list of permissions (strings and/or objects).
 * @param  {String} operation The operation for which we want to check the permission
 * @return {Promise} A promise resolving with true if the operation is
 * authorized, false otherwise.
 */
RBAC.prototype.canPermissionString = function(role, operation) {
    if (! _.isArray(role.can)) {
        throw TypeError('role.can is not an array');
    } else if (! _.isString(operation)) {
        throw TypeError('operation is not a string');
    }
    return Q.when(_.indexOf(role.can, operation) > -1);
};

/**
 * Verify that an operation is authorized for a given role following parameters.
 * @param  {Object} roleFound [description]
 * @param  {String} operation [description]
 * @param  {Object} params    [description]
 * @return {Promise.<Boolean>}           [description]
 */
RBAC.prototype.canPermissionFunction = function(roleFound, operation, params) {
    if (! _.isPlainObject(roleFound)) {
        // TODO Error handling
    } else if (! _.isString(operation)) {
        // TODO Error handling
    } else if (_.isUndefined(params)) {
        // TODO Error handling
    }
    var permission = _.find(roleFound.can, (o) => {
        return o.name === operation;
    });
    if (_.isUndefined(permission)) {
        return Q.when(false);
    } else {
        return Q.when(permission.when(params));
    }
};

/**
 * Retrieves a role inside the roles configuration given for object creation.
 * The role can be written as 'role.subrole' if the roles configuration is in
 * depth.
 * @param  {String} roleName The full name of the role
 * @return {Object}          The role found
 */
RBAC.prototype.findRole = function(roleName) {
    if (! _.isString(roleName)) {
        // TODO Error handling
    }
    var roleSplit = roleName.split('.');
    var foundRole = this.roles[roleSplit[0]];
    _.map(roleSplit.splice(1), (subRole) => {
        foundRole = foundRole[subRole];
    });
    return foundRole;
};

/**
 * Verify that an operation is permitted, given a set of roles and optionally
 * parameters to verify for the operation.
 * @param  {Array.<String>} roles     The roles to check
 * @param  {String} operation The operation to verify
 * @param  {Object} params    Named parameters to verify the operation (optional,
 * needed only if the operation check is a function)
 * @return {Promise}           Promise resolving in true if one of the roles
 * allows the operation, false otherwise.
 */
RBAC.prototype.can = function(roles, operation, params) {
    if (! _.isArray(roles)) {
        // TODO Error handling
    } else if (! _.isString(operation)) {
        // TODO Error handling
    }
    var self = this;
    return Q.all(
        _.map(roles, (role) => {
            return self._oneRoleCan(role, operation, params);
        })
    ).then((res) => {
        return Q.when(res.indexOf(true) > -1);
    });
};

/**
 * Verify that an operation is permitted, given a role and optionally
 * parameters to verify for the operation.
 * @param  {String} role      The name of the role to check
 * @param  {String} operation The name of the operation
 * @param  {[Object]} params    Named parameters to verify the operation (optional,
 * needed ony if the operation check is a function)
 * @return {Promise}           Promise resolving in true if the role allows the
 * operation, false otherwise.
 */
RBAC.prototype._oneRoleCan = function(role, operation, params) {
    if (! _.isString(role)) {
        // TODO Error handling
    } else if (! _.isString(operation)) {
        // TODO Error handling
    }
    var self = this;
    let foundRole = self.findRole(role);
    let verificationFunc = _.isUndefined(params) ? self.canPermissionString : self.canPermissionFunction;

    return verificationFunc(foundRole, operation, params).then((res) => {
        if (!res &&
            foundRole.inherits &&
            foundRole.inherits.length > 0) {
            // look through inherited role
            return self.can(foundRole.inherits, operation, params);
        } else {
            return Q.when(res);
        }
    });
};

module.exports = RBAC;
