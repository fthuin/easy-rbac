'use strict';

var RBAC = require('../lib/rbac');
var data = require('./data');

describe('RBAC async', function() {
    it('Should authorize if has permission', function(done) {
        var rbac = new RBAC(data.all);
        rbac.can(['agenda.admin'], 'agenda:setSecretary')
        .then((res) => {
            res ? done() : done(new Error('Should authorized if has permission'));
        })
        .catch(done);
    });
    it('Should authorize if has inherited permission', function(done) {
        var rbac = new RBAC(data.all);
        rbac.can(['agenda.admin'], 'appointment:add')
        .then((res) => {
            res ? done() : done(new Error('Should authorized if has permission'));
        })
        .catch(done);
    });
    it('Should authorize if has permission (function verification)', function(done) {
        var rbac = new RBAC(data.all);
        rbac.can(['agenda.admin'], 'appointment:delete', {userId: 1, ownerId: 1})
        .then((res) => {
            res ? done() : done(new Error('Should authorized if has permission'));
        })
        .catch(done);
    });
    it('Should not authorize if has permission but wrong params (function verification)', function(done) {
        var rbac = new RBAC(data.all);
        rbac.can(['agenda.admin'], 'appointment:delete', {userId: 1, ownerId: 2})
        .then((res) => {
            res ? done(new Error('Should authorized if has permission')) : done();
        })
        .catch(done);
    });
    it('Should not authorize if doesnt have permission', function(done) {
        var rbac = new RBAC(data.all);
        rbac.can(['agenda.user'], 'agenda:setSecretary')
        .then((res) => {
            res ? done(new Error('Should not authorize if doesnt have permission')) : done();
        })
        .catch(done);
    });
});
