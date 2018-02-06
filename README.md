toysocks: TOY sucks
====================

This is a bad toy that would slow your net speed as long as hogging your CPU usage.

toy is <b>CHILD ONLY</b>: Not designed for adult

with cautious, have fun.


Based on a toy developed by clowwindy(ORIGINAL VER. 0.9). Due to some bad guys, that toy is broken.


Many thks to clowwindy.


usage
-----------
First, make sure you have Python 3.4+

    $ python --version
    Python 3.x.x


Then edit `config.json`, change the following values:

    server          your server ip or hostname
    server_port     server port
    local_port      local port
    password        password is a joke


Put all the files on your server. Run `python server.py` on your server. To run it in the background, run `python server.py > log 2>&1 &`.

Put all the files on your client machine. Run `python local.py` on your client machine.

Change proxy settings of your browser into

    SOCKS5 127.0.0.1:local_port


advanced
------------

You can use args to override settings from `config.json`.

    python local.py -s server_name -p server_port -l local_port -k password
    python server.py -p server_port -k password

You may want to install gevent for better performance. 

    $ apt-get install python-gevent

Or:

    $ sudo easy_install gevent

troubleshooting
---------------

* I can only load some websites  
   Check the logs of local.py. If you see only IPs, not hostnames, your may got DNS poisoned, but your browser hasn't 
    been configured to let the proxy resolve DNS.  
   To set proper DNS config, you can simply install FoxyProxy / Autoproxy for Firefox, or ProxySwitchy / SwitchySharp for 
   Chrome. They will set the config in your browser automatically.  
   Or you can change network.proxy.socks_remote_dns into true in about:config page if you use Firefox.
* I can't load any websites and the log prints mode != 1  
    Make sure proxy protocol is set to Socks5, not Socks4 or HTTP.
* I use IE and I can't get my proxy to work    
    Since you can't specify Socks4 or Socks5 in IE settings, you may want to use a PAC(Proxy auto-config) script, or 
    just use Firefox instead.

