Python flask app

CTF app for a single user/single machine. 

Basically, config.py file contains flag, filename, and a command.

When user enters a flag, the index page gets replaced with data from the filename, and the command is ran.

Allows you to develop a storyline like CTF. User finds the flag, index page/"quest" gets updated, and command could be ran to start a docker container or something.