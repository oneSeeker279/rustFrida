// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_getFieldAuto are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _getFieldAuto = Java._getFieldAuto;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._getFieldAuto;

    // Wrap a raw Java object pointer as a Proxy for field access via dot notation.
    // e.g. ctx.thisObj.mTitle reads the mTitle field via JNI reflection.
    function _wrapJavaObj(ptr, cls) {
        return new Proxy({__jptr: ptr, __jclass: cls}, {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                var result = _getFieldAuto(target.__jptr, target.__jclass, prop);
                // Object fields come back as {__jptr, __jclass} — wrap recursively
                if (result !== null && typeof result === "object"
                    && result.__jptr !== undefined) {
                    return _wrapJavaObj(result.__jptr, result.__jclass);
                }
                return result;
            }
        });
    }

    function MethodWrapper(cls, method, sig) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
    }

    MethodWrapper.prototype.overload = function(sig) {
        return new MethodWrapper(this._c, this._m, sig);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var sig = this._s;
            var name = this._m === "$init" ? "<init>" : this._m;
            if (!sig) {
                var ms = _methods(this._c);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + this._c + "." + this._m);
                if (match.length > 1) {
                    var s = match.map(function(m) { return m.sig; }).join(", ");
                    throw new Error(this._m + " has " + match.length +
                        " overloads, use .overload(sig): " + s);
                }
                sig = match[0].sig;
            }
            if (fn === null || fn === undefined) {
                _unhook(this._c, name, sig);
                this._fn = null;
            } else {
                var cls = this._c;
                var userFn = fn;
                _hook(this._c, name, sig, function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    return userFn(ctx);
                });
                this._fn = fn;
            }
        }
    });

    Java.use = function(cls) {
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                return new MethodWrapper(cls, prop);
            }
        });
    };
})();
