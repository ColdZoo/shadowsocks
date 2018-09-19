var WebChannelType = {
	init: "init",
	signal: "signal",
	response: "response"
}

var WebChannel = function(transport, initCallback){
    if (typeof transport !== "object" || typeof transport.send !== "function") {
        console.error("The WebChannel expects a transport object with a send function and onmessage callback property." +
                      " Given is: transport: " + typeof(transport) + ", transport.send: " + typeof(transport.send));
        return;
    }

    var channel = this;
    this.transport = transport;

    this.send = function(data)
    {
        if (typeof(data) !== "string") {
            data = JSON.stringify(data);
        }
        console.log("send:" + data);
        channel.transport.send(data);
    }

    this.transport.onmessage = function(message)
    {
        var data = message.data;
        if (typeof data === "string") {
            data = JSON.parse(data);
        }
        switch (data.type) {
            case WebChannelType.init:
                channel.handleInit(data);
                break;
            case WebChannelType.response:
                channel.handleResponse(data);
                break;
            case WebChannelType.signal:
                channel.handleSignal(data);
                break;
            default:
                console.error("invalid message received:", message.data);
                break;
        }
    }

    this.objects = {};
    this.handleInit = function(data)
    {
    	for (var classname in data){
    		var objlist = data[classname]["objectlist"];
    		for (var i = 0; objlist && i < objlist.length; i++){
    			new WebObject(classname, objlist[i], data[classname], channel);
    		}    		
    	}
    	if (initCallback) initCallback(channel);
    }

    this.handleResponse = function(data){
    	var _objname = data.objname;
    	var _funcname = data.funcname;
    	var _return = data.return;
    	//try{
	    	var _responseCallback = channel.objects[_objname].__responseCallback__[_funcname];
	    	if (_responseCallback) _responseCallback(_return);
	    	//delete channel.objects[_objname].__responseCallback__[_funcname];
    	// }catch(e){
    	// 	console.log("WebChannel response error: " + e);
    	// }
    }

    this.handleSignal = function(data){
    	var _objname = data.objname;
    	var _funcname = data.funcname;
    	var _params = data.params;
    	//try{
	    	var _signalCallback = channel.objects[_objname].__signalCallback__[_funcname];
	    	if (_signalCallback) _signalCallback.apply(_signalCallback, _params);
    	// }catch(e){
    	// 	console.log("WebChannel onsignal error: " + e);
    	// }
    }

}

function WebObject(classname, name, data, webChannel)
{
	var self = this;
	this.__class__ = classname;
	this.__id__ = name;
	this.__signalCallback__ = {};
	this.__responseCallback__ = {};

	webChannel.objects[name] = this;
	var object = this;

	for (var i = 0; i < data["funcsignallist"].length; i++){
		var methodSignal = data["funcsignallist"][i];
		object[methodSignal] = {
			connect: function(callback) {
                if (typeof(callback) !== "function") {
                    console.error("Bad callback given to connect to signal " + signalName);
                    return;
                }
                object.__signalCallback__[methodSignal] = callback;
            },
			disconnect: function(callback){
				var _methodname = "";
				for (var _name in object.__signalCallback__){
					if (object.__signalCallback__[_name] == callback){
						_methodname = _name;
						break;
					}
				}
				delete object.__signalCallback__[_methodname];
			}
		}
	}

	var addMethod = function(methodResponse){
		object[methodResponse] = function(){
			var response = {
				objname: object.__id__,
				funcname: methodResponse,
				params: [],
			};
			var callback;
			for (var j = 0; j < arguments.length; ++j) {
	            if (typeof arguments[j] === "function")
	                callback = arguments[j];
	            else
	                response.params.push(arguments[j]);
	        }
	        if (callback) object.__responseCallback__[methodResponse] = callback;

	        webChannel.send(response);			
		}

	};

	data["funcrequestlist"].forEach(addMethod);
/*	for (var i = 0; i < data["funcrequestlist"].length; i++){
		var methodResponse = data["funcrequestlist"][i];
		object[methodResponse] = 
	}*/
}
