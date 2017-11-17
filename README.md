# Fritz!box logs

A library that aims to parse logs from a Fritz!Box routers.

This crate as a library is basically a function that loads a text log into
memory in a structured manner.

## Obtaining logs

To load the current logs from your fritz!box router you can use a simple python
module like [fritzconnection](https://pypi.python.org/pypi/fritzconnection).
Here's a one-liner for it (on linux):

```sh
% python -c "from fritzconnection import FritzConnection; \
             from getpass import getpass; \
             conn = FritzConnection(password=getpass()); \
             logs = conn.call_action('DeviceInfo:1', 'GetDeviceLog'); \
             print(logs['NewDeviceLog'])" > logs.txt
```

It will ask you for your password (i.e. the one you enter to access the router
via web browser) and save all available logs to the 'logs.txt' file.

## Why?

Well, I used to have some serious issues with my ISP and I needed to run some
logs analysis. First of all, I've discovered that this *router* doesn't have a
persistent storage for its logs (*sick*). I never expected anything like that,
seriously. Second of all, I had to do the analysis by hand (like how often a
recconection happen). So I realized that I have to make my own way out of the
XVIII century and created this simple tool. (Un)fortunately I didn't have to
examine the logs since I've started to work on the tool so its development is
not running as fast anymore and I haven't implemented any real analysis so far,
but I totally realize it is only a matter of time when I need it again, so I'll
be working on the crate until it provides some basic statistics functions at the
very least.
