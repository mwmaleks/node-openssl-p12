var _ =       require('underscore.deferred');


function getA(a) {
    var deferred = _.Deferred();
    console.log('a', a, a + 1);
    setTimeout(function() {
        deferred.resolve(a + 1);
    },100);
    return deferred;
}

function getB(b) {
    var deferred = _.Deferred();
    console.log('b', b, b + 3);
    setTimeout(function() {
        deferred.resolve(b + 3);
    }, 200);
    return deferred;
}

function getC(c) {
    var deferred = _.Deferred();
    console.log('c', c, c + 5);
    setTimeout(function() {
        deferred.resolve(c + 5);
    }, 100);
    return deferred;
}



var dfd = _.Deferred();
   dfd.then(null, getA)
       .then(getB)
       .then(getC)
       .then(function(v) {
           console.log(v);
       })
   ;

dfd.reject(1);