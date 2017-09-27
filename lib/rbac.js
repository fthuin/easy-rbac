'use strict';

var Q = require('q');
var _ = require('lodash');

function RBAC(roles) {
    this._init = false;
    this._inited = false;
    this.init(roles);
}

RBAC.create = function create(opts) {
    return new RBAC(opts);
};

RBAC.prototype.init = function init(roles) {
    var $this = this;
    // If opts is a function execute for async loading
    if (_.isFunction(roles)) {
        $this._init = Q.nfcall(roles).then(function(data) {
            return $this.init(data);
        });
        return;
    }
    // If not a function then should be object
    if (!_.isPlainObject(roles)) {
        throw new TypeError('Expected input to be function or object');
    }

    var map = {};

    // Standardize roles
    _.forIn(roles, (value, key, object) => {
        map[key] = {
            can: {}
        };
        if (!_.isArray(roles[key].can)) {
            throw new TypeError('Expected roles[' + key + '].can to be an array');
        }
        if (value.inherits) {
            if (!_.isArray(value.inherits)) {
                throw new TypeError('Expected roles[' + key + '].inherits to be an array');
            }
            map[key].inherits = [];
            _.each(roles[key].inherits, (value, index, array) => {
                if (!_.isString(value)) {
                    throw new TypeError('Expected roles[' + key + '].inherits element to be a String');
                }
                if (!roles[value]) {
                    throw new TypeError('Undefined inheritance role: ' + value);
                }
                map[key].inherits.push(value);
            });
        }

        _.each(roles[key].can, (value, index, array) => {
            if (_.isString(value)) {
                map[key].can[value] = 1;
                return;
            }
            if (_.isFunction(value.when) && _.isString(value.name)) {
                map[key].can[value.name] = value.when;
                return;
            }
            throw new TypeError('Unexpected operation type', value);
        });
    });

    // Add roles to class and mark as inited
    $this.roles = map;
    $this._inited = true;
};

RBAC.prototype.can = function can(role, operation, params, cb) {
    var $this = this;
    // If not inited then wait until init finishes
    if (!$this._inited) {
        return $this._init.then(function() {
            return $this.can(role, operation, params, cb);
        });
    }

    if (_.isFunction(params)) {
        cb = params;
        params = undefined;
    }

    var promise = Q.Promise(function(resolve, reject) {

        if (!_.isString(role)) {
            throw new TypeError('Expected first parameter to be string : role');
        }

        if (!_.isString(operation)) {
            throw new TypeError('Expected second parameter to be string : operation');
        }

        var $role = $this.roles[role];

        if (!$role) {
            throw new Error('Undefined role');
        }

        // IF this operation is not defined at current level try higher
        if (!$role.can[operation]) {
            // If no parents reject
            if (!$role.inherits || $role.inherits.length < 1) {
                return reject(new Error('unauthorized'));
            }
            // Return if any parent resolves true or all reject
            return Q.any($role.inherits.map(function(parent) {
                return $this.can(parent, operation, params);
            })).then(resolve, function(err) {
                if (err.message === "Can't get fulfillment value from any promise, all promises were rejected.") {
                    reject(new Error('unauthorized'));
                    return;
                }
                reject(err);
            });
        }

        // We have the operation resolve
        if ($role.can[operation] === 1) {
            return resolve(true);
        }

        // Operation is conditional, run async function
        if (_.isFunction($role.can[operation])) {
            $role.can[operation](params, function(err, result) {
                if (err) {
                    return reject(err);
                }
                if (!result) {
                    return reject(new Error('unauthorized'));
                }
                resolve(true);
            });
            return;
        }
        // No operation reject as false
        reject(false);
    });

    if (_.isFunction(cb)) {
        promise.then(function(can) {
            cb(null, can);
        }, function(err) {
            if (err.message !== 'unauthorized' &&
                err.message !== "Can't get fulfillment value from any promise, all promises were rejected.") {
                cb(err);
                return;
            }
            cb(null, false);
        });
    }

    return promise;
};

module.exports = RBAC;
