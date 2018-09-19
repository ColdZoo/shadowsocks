var Network = {};
Network.wsurl = "ws://localhost:12758";

Network.init = function(events, evcalls){
  var socket = new WebSocket(Network.wsurl);
  socket.onclose = function()
  {
      console.error("web channel closed");
      Network.config = null;
  };
  socket.onerror = function(error)
  {
      console.error("web channel error: " + error);
      Network.config = null;
  };
  socket.onopen = function()
  {
      Network.channel = new WebChannel(socket, function(channel) {
          Network.config = channel.objects.config;
          for (var obj in events){
            for (var ev in events[obj]){
              channel.objects[obj][ev].connect(events[obj][ev]);
            }
          }

          for (var obj in evcalls){
            for (var ev in evcalls[obj]){
              channel.objects[obj][ev](evcalls[obj][ev]);
            }
          }
          console.log("通信模块就绪!");
      });
  }
}
