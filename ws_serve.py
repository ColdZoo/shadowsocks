
import time
import threading
import json
from websocket_server import WebsocketServer

# Called when a client sends a message
def message_received(client, server, message):
    if len(message) > 200:
        message = message[:200]+'..'
    print("Client(%d) said: %s" % (client['id'], message))
    try:
        msg = json.loads(message)
        if msg['type'] == "GET":
            response = json.dumps({"port":1081})
            WebsocketServer.send_message(server, client, response)
            print('config sent')
        if msg['type'] == "SET":
            config = msg["conf"]
            print(config)
            print('config updated!')
    except Exception as e:
        pass


class WSThread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        self.server.run_forever()



PORT = 12758
cfg_server = WebsocketServer(PORT)
cfg_server.set_fn_message_received(message_received)
t_ws = WSThread(cfg_server)
t_ws.start()
print('SLEEP')
time.sleep(10)
cfg_server.shutdown()
t_ws.join()
print('SHUTDOWN')




