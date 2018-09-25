import json
from websocket_server import WebsocketServer

# Called for every client connecting (after handshake)
def web_client_connect(client, server):
	print("New client connected and was given id %d" % client['id'])
	server.send_message(client, g_channel.toJson())

# Called for every client disconnecting
def web_client_disconnect(client, server):
	if (client):
		print("Client(%d) has disconnected" % client['id'])
	else:
		print("One Client has disconnected")

# Called when a client sends a message
def web_msg_recived(client, server, message):
	bytemsg = bytearray([ord(x) for x in message]) #WebSocket在接收数据时，将中文字节流转成了字符串，这里需要将字符串还原为字节流，再进行解码变了正常的UTF8字符串
	strmsg = bytemsg.decode("utf-8")

	obj = json.loads(strmsg)
	if (not obj or ("objname" not in obj) or ("funcname" not in obj)):
		print("Error: recv msg is error format! [", message, "]")
		return
	ret = {"type": "response",
		   "objname": obj["objname"],
		   "funcname": obj["funcname"]}
	ret["return"] = g_channel.request(obj["objname"], obj["funcname"], obj["params"])
	server.send_message(client, json.dumps(ret, ensure_ascii=False))


#用作信号，推送消息给前端
def web_signal(type):
	def func_wrapper(signal_func):
		def wrapper(self, *args, **kwargs):
			try:
				ret = {"type":"signal"}
				_info = g_channel.objectlist[self.__class__.__name__]
				for objname in _info["objectlist"]:
					if (_info["objectlist"][objname] == self):
						ret["objname"] = objname
						break
				ret["funcname"] = signal_func.__name__
				ret["params"] = []
				for para in args:
					ret["params"].append(para)
					
				#ret["return"] = signal_func(self, *args, **kwargs)
				print("signal: %s() called" % signal_func.__name__, ret)
				g_channel.server.send_message_to_all(json.dumps(ret))
			except Exception as e:
				print('Error: ', e.message)
		g_channel.registSignal(type, signal_func)
#		funcnamelist.append(signal_func.__name__)
		return wrapper
	return func_wrapper

#前端请求，执行后台处理，并将结果返回给前端
def web_request(type):
	def func_wrapper(request_func):
		def wrapper(self, *args, **kwargs):
			try:
				ret = request_func(self, *args, **kwargs)
				print("request: %s() called" % request_func.__name__, ret)
				return ret
			except Exception as e:
				print('Error: ', e.message)
		g_channel.registRequest(type, request_func)
		return wrapper
	return func_wrapper

class WebChannel(object):
	"""docstring for WebChannel"""
	def __init__(self):
		self.objectlist = {}

	def runserver(self, port, host='127.0.0.1'):
		self.server = WebsocketServer(port, host)
		self.server.set_fn_new_client(web_client_connect)
		self.server.set_fn_client_left(web_client_disconnect)
		self.server.set_fn_message_received(web_msg_recived)
		print('websocket run ', host, ':', port)
#		self.server.run_forever()

	def registObject(self, name, obj):
		type = obj.__class__.__name__
		if (type not in self.objectlist):
			self.objectlist[type] = {"objectlist":{}}
		elif ("objectlist" not in self.objectlist[type]):
			self.objectlist[type]["objectlist"] = {}

#		print("regist obj: ", name)
		self.objectlist[type]["objectlist"][name] = obj

	def registSignal(self, type, func):
		if (type not in self.objectlist):
			self.objectlist[type] = {"funcsignallist":{}}
		elif ("funcsignallist" not in self.objectlist[type]):
			self.objectlist[type]["funcsignallist"] = {}

#		print("registSignal:", type, func.__name__)
		self.objectlist[type]["funcsignallist"][func.__name__] = func

	def registRequest(self, type, func):
		if (type not in self.objectlist):
			self.objectlist[type] = {"funcrequestlist":{}}
		elif ("funcrequestlist" not in self.objectlist[type]):
			self.objectlist[type]["funcrequestlist"] = {}

#		print("registRequest:", type, func.__name__)
		self.objectlist[type]["funcrequestlist"][func.__name__] = func

	def request(self, objname, funcname, params):
		print("recv [", objname, "]:", funcname)
		for type in self.objectlist:
			_info = self.objectlist[type]
			for name in _info["objectlist"]:
				if (name == objname):
					if (funcname in _info["funcrequestlist"]):
						return _info["funcrequestlist"][funcname](_info["objectlist"][name], *params)

	def toJson(self):
		strJson = {"type":"init"}
		for type in self.objectlist:
			strJson[type] = {"objectlist": [],
							 "funcsignallist": [],
							 "funcrequestlist":[]}

			_info = self.objectlist[type]
			for name in _info["objectlist"]:
				strJson[type]["objectlist"].append(name)

			for name in _info["funcsignallist"]:
				strJson[type]["funcsignallist"].append(name)

			for name in _info["funcrequestlist"]:
				strJson[type]["funcrequestlist"].append(name)

		return json.dumps(strJson)

g_channel = WebChannel()

