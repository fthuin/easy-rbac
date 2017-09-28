'use strict';

const Q = require('q');

var roles = {};

roles.agenda = {
    user: {
        can: ['appointment:watch']
    },
    secretary: {
        can: ['appointment:add', {
            name: 'appointment:delete',
            when: function(params) {
                return params.userId === params.ownerId;
            }
        }],
        inherits: ['agenda.user']
    },
    admin: {
        can: ['agenda:setSecretary', 'agenda:setAdmin'],
        inherits: ['agenda.secretary']
    }
};

roles.members = {
    user: {
        can: ['watch']
    },
    moderator: {
        can: ['member:delete', 'member:add'],
        inherits: ['members.user']
    },
    admin: {
        can: ['member:setModerator', 'member:setAdmin'],
        inherits: ['members.moderator']
    }
};

module.exports.all = roles;
