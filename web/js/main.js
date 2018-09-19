window.onload = function(){
  Network.init({
    config: {
      onMessage: Work.onServerMessage,
    }
  }, {
    config: {
      getConfig: Work.initConfig,
    }
  });
}

var Work = {};

Work.onServerMessage = function(msg){
  $.Pop(msg, { Class: "pop_msg", Title: '提示', Btn:{ no:null }});
}

Work.initConfig = function(config){
  Work.config = config;
  d3.select(".conf_server").node().value = config.server;
  d3.select(".conf_serverport").node().value = config.server_port;
  d3.select(".conf_localport").node().value = config.local_port;
  d3.select(".conf_timeout").node().value = config.timeout;

}

Work.changeConfig = function(){
  if (!Network || !Network.config) return;

  $.Pop("确认修改配置?", { Class: "pop_msg", Title: '提示', Btn:{
    yes:{vla:"确定"}
  }}, function(){
    Work.config.server = d3.select(".conf_server").node().value;
    Work.config.server_port = d3.select(".conf_serverport").node().value;
    Work.config.local_port = d3.select(".conf_localport").node().value;
    var pswd = d3.select(".conf_psw").node().value;
    if (pswd != "********") Work.config.password = pswd;
    Work.config.timeout = d3.select(".conf_timeout").node().value;
    Network.config.setConfig(Work.config);
  });
}