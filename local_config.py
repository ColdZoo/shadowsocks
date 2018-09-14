import os
import json
from websocket_server.webchannel import web_signal, web_request, g_channel

class ConfigModel(object):
  """docstring for WebModel"""
  def __init__(self, changeCallback):
    with open('config.json', 'r') as f:
      text = f.read()
      bytedata = bytearray([ord(x) for x in text]) #WebSocket在接收数据时，将中文字节流转成了字符串，这里需要将字符串还原为字节流，再进行解码变了正常的UTF8字符串
      data = bytedata.decode("utf-8")
      self.config = json.loads(data)
    self.changeCallback = changeCallback

  @web_request("ConfigModel") #前端请求，执行后台处理，并将结果返回给前端
  def getConfig(self):
    return self.config

  @web_request("ConfigModel") #用作信号，推送消息给前端
  def setConfig(self, config):
    if (self.config == config):
      print('config is sample!')
      return False

    self.config = config
    with open('config.json', 'w') as f:
      text = json.dumps(config, ensure_ascii=False)
      f.write(text)
      print('config save to file, done!')

    if (self.changeCallback):
      self.changeCallback(config)

    return True

  @web_signal("ConfigModel") #用作信号，推送消息给前端
  def onMessage(self, msg):
    pass

