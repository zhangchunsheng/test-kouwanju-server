/**
 * Copyright(c)2013,Wozlla,www.wozlla.com
 * Version: 1.0
 * Author: Peter Zhang
 * Date: 2013-09-21
 * Description: app
 */
/**
 * Module dependencies
 */
var EventEmitter = require('events').EventEmitter;
var util = require('util');
var io = require('socket.io-client');
var crypto = require('crypto');

var ePomelo = function (opts) {
	EventEmitter.call(this);
	this._socket = null;
	this._id = 1;
	this._callbacks = {};
	this._debug = false;
	this._filters = [];
	this._signer = null;
};

util.inherits(ePomelo, EventEmitter);

/**
 * Pomelo
 */
//var pomelo     = new ePomelo;
//module.exports = pomelo;
module.exports = ePomelo;

var pomelo = ePomelo.prototype;

// Protocol
var Protocol = {};

var HEADER = 5;

var Message = function (id, route, body) {
	this.id = id;
	this.route = route;
	this.body = body;
};

var bt2Str = function (byteArray, start, end) {
	var result = "";
	for (var i = start; i < byteArray.length && i < end; i++) {
		result = result + String.fromCharCode(byteArray[i]);
	}
	return result;
};

/**
 *pomele client encode
 */
Protocol.encode = function (id, route, msg) {
	//	var data = {'id':id, 'route':route, 'msg':msg};
	//	return JSON.stringify(data);

	var msgStr = JSON.stringify(msg);
	if (route.length > 255) {
		throw new Error('route maxlength is overflow');
	}
	var byteArray = new Uint16Array(HEADER + route.length + msgStr.length);
	var index = 0;
	byteArray[index++] = (id >> 24) & 0xFF;
	byteArray[index++] = (id >> 16) & 0xFF;
	byteArray[index++] = (id >> 8) & 0xFF;
	byteArray[index++] = id & 0xFF;
	byteArray[index++] = route.length & 0xFF;
	for (var i = 0; i < route.length; i++) {
		byteArray[index++] = route.charCodeAt(i);
	}
	for (var i = 0; i < msgStr.length; i++) {
		byteArray[index++] = msgStr.charCodeAt(i);
	}
	return bt2Str(byteArray, 0, byteArray.length);
};

/**
 *client decode
 */
Protocol.decode = function (msg) {
	//	var data = JSON.parse(msg);
	//	return new Message(data.id, data.route, data.msg);
	var idx,
	len = msg.length,
	arr = new Array(len);
	for (idx = 0; idx < len; ++idx) {
		arr[idx] = msg.charCodeAt(idx);
	}
	var index = 0;
	var buf = new Uint16Array(arr);
	var id = ((buf[index++] << 24) | (buf[index++]) << 16 | (buf[index++]) << 8 | buf[index++]) >>> 0;
	var routeLen = buf[HEADER - 1];
	var route = bt2Str(buf, HEADER, routeLen + HEADER);
	var body = bt2Str(buf, routeLen + HEADER, buf.length);
	return new Message(id, route, body);
};

var id = 1;
var _callbacks = {};
/**
 * Init Pomelo
 */
pomelo.init = function (params, cb) {
	var self = this;
	this.params = params;

	var host = params.host;
	var port = params.port;
	this.encode = params.encode || defaultEncode;

	var url = 'ws://' + host;
	if (port) {
		url += ':' + port;
	}

	var socket = this._socket = io.connect(url, {
			'force new connection' : true,
			reconnect : true
		});
	socket.on('connect', function () {
		self._debug && console.log('[pomeloclient.init] websocket connected!');
		if (cb) {
			cb(socket);
		}
	});

	socket.on('reconnect', function () {
		self._debug && console.log('reconnect');
	});

	socket.on('message', function (data) {
		if (typeof data === 'string') {
			data = JSON.parse(data);
		}
		if (data instanceof Array) {
			processMessageBatch(self, data);
		} else {
			processMessage(self, data);
		}
	});

	socket.on('error', function (err) {
		self._debug && console.log(err);
	});

	socket.on('disconnect', function (reason) {
		self._debug && console.log('disconnect');
	});
};

var defaultEncode = pomelo.encode = function (reqId, route, msg) {
	return Protocol.encode(id, route, msg);
};

/**
 * Request
 */
pomelo.request = function (route) {
	if (!route) {
		return;
	}
	var msg = {};
	var cb;
	arguments = Array.prototype.slice.apply(arguments);
	if (arguments.length === 2) {
		if (typeof arguments[1] === 'function') {
			cb = arguments[1];
		} else if (typeof arguments[1] === 'object') {
			msg = arguments[1];
		}
	} else if (arguments.length === 3) {
		msg = arguments[1];
		cb = arguments[2];
	}

	id++;
	_callbacks[id] = cb;

	pomelo.sendMessage(id, route, msg);
};

pomelo.sendMessage = function (reqId, route, msg) {
	var socket = this._socket;
	if (this.encode) {
		msg = this.encode(reqId, route, msg);
	}
	socket.send(msg);
};

pomelo.setMd5Sign = function (secret_key) {
	function localCmp(str1, str2) {
		return str1.localeCompare(str2);
	}

	function md5(str) {
		var md5 = crypto.createHash('md5');
		try {
			md5.update(str);
			return md5.digest('hex');
		} catch (e) {
			return false;
		}
	}

	this._signer = function (msg, route) {

		//add timestamp
		msg._ts = Math.round(new Date().getTime() / 1000);

		var keys = Object.keys(msg);
		keys.sort(localCmp);
		var sign_str = route;
		keys.forEach(function (key) {
			if (typeof msg[key] !== 'object')
				sign_str += msg[key];
		});
		sign_str += secret_key;
		msg.sign = md5(sign_str);
	}
}

/**
 * Notify
 */
pomelo.notify = function (route, msg) {
	this.request(route, msg);
};

pomelo.disconnect = function () {
	var socket = this._socket;
	if (socket) {
		socket.disconnect();
		socket = null;
	}
};

var Message = function (id, route, body) {
	this.id = id;
	this.route = route;
	this.body = body;
};

/**
 * Process Message
 */
var processMessage = function (client, msg) {
	var route;

	if (msg.id) {
		//if have a id then find the callback function with the request
		var cb = _callbacks[msg.id];
		delete _callbacks[msg.id];
		if (typeof cb !== 'function') {
			client._debug && console.log('[pomeloclient.processMessage] cb is not a function for request ' + msg.id);
			return;
		}
		cb(msg.body);
		return;
	}

	// server push message or old format message
	processCall(msg);

	//if no id then it should be a server push message
	function processCall(msg) {
		var route = msg.route;
		if (!!route) {
			if (!!msg.body) {
				var body = msg.body.body;
				if (!body) {
					body = msg.body;
				}
				client.emit(route, body);
			} else {
				client.emit(route, msg);
			}
		} else {
			client.emit(msg.body.route, msg.body);
		}
	}
};

var processMessageBatch = function (client, msgs) {
	for (var i = 0, l = msgs.length; i < l; i++) {
		processMessage(client, msgs[i]);
	}
};

var GATE_HOST = "192.168.1.22";
var GATE_PORT = 6014;

function authEntry(uid, sessionId, token, callback) {
	queryEntry(uid, function (host, port) {
		entry(host, port, sessionId, token, callback);
	});
}

function queryEntry(uid, callback) {
	pomelo.init({
		host : GATE_HOST,
		port : GATE_PORT,
		user : {},
		handshakeCallback : function () {}
	}, function () {
		console.log('success');

		/*pomelo.request("gate.gateHandler.queryEntry", {
		uid: 1
		}, function(data) {
		pomelo.disconnect();
		console.log(data);
		callback(data.host, data.port);
		});*/
		pomelo.request("gate.gateHandler.queryServerList", {
			uid : 1
		}, function (data) {
			console.log(data);
			pomelo.disconnect();
			callback(data.serverLists[0].connectors.host, data.serverLists[0].connectors.port);
		});
	});
}

function entry(host, port, sessionId, token, callback) {
	// init socketClient
	// TODO for development
	if (host === '127.0.0.1') {
		host = GATE_HOST;
	}
	pomelo.init({
		host : host,
		port : port,
		log : true
	}, function () {
		console.log("connector.entryHandler.entry");
		pomelo.request('connector.entryHandler.entry', {
			sessionId : sessionId,
			token : token,
			serverId : 1
		}, function (data) {
			console.log(data);

			if (callback) {
				callback(data);
			}

			if (data.code == 1001) {
				alert('Login fail!');
				return;
			} else if (data.code == 1003) {
				alert('loginName not exists!');
				return;
			}

			if (data.code != 200) {
				alert('Login Fail!');
				return;
			}
		});

		/*console.log('connector.roleHandler.createMainPlayer');
		pomelo.request('connector.roleHandler.createMainPlayer', {
		sessionId: sessionId,
		token: token,
		cId: 1,
		nickname: "hello"
		}, function(data) {
		console.log(data);
		});*/

		/*console.log('battle.battleHandler.fight');
		pomelo.request('battle.battleHandler.fight', {
		sessionId: sessionId,
		token: token
		}, function(data) {
		console.log(data);
		});*/
	});
}

var data = {
	uid : 1,
	loginName : "wozlla",
	registerType : 1,
	sessionId : "729B28D90AB2E90B494F7DD71976666F",
	token : "6d90953e70d8e81e25b461f515a4a6cb159e74ea3067c71b92d862e3ad9c61e5"
};

console.log(data);
authEntry(data.uid, data.sessionId, data.token, function (data) {
	console.log(data);
});
