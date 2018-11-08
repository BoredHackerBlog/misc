Code and configs for a b0mb, for an escape room.

b0mbcode.py is responsible for GPIO and timing.

Hostapd is for starting a wireless access point.

For the escape room task, the raspberry pi/b0mb is found using a wireless signal analyzer app, b0mbcode.py is provided to the player, and player defuses the b0mb by disconnecting a GPIO pin.