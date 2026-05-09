# api_server_in_c
This is a repo to build an API Server in C

# Pre requisite 
you have to install :<br>
cmake, pkg-config, mysql-client, libsodium and libuuid :<br>
for macOs user :<br>
```brew install cmake pkg-config mysql-client```

for linux user :<br>
```apt install cmake pkg-config libmysqlclient-dev```

You also need to install ```docker``` and ```docker compose``` for launching the DB.<br>

# Build the project
Create a directory name ```build/``` on the project root<br>
Then, in this directory make the command : ```$ cmake ../ && make``` <br>
Before run the API, you have to launch the DB Server with :<br>
```docker compose up -d``` from the project root.<br>
You also need to create a new ```.env``` on the root of the project. You can take the exemple from ```.env.exemple```
This will create the binary ```api_server``` in the directory ```build/```. <br>
<br>
If the CMakeLists.txt change, we need to relaunch ```$ cmake ../ && make``` from the ```build/``` directory.<br>

# Lunch the server
Before lunch the server, and make sure you're in the ```build/``` directory before lunch ```$ ./api_server``` <br>

# GIT
Find way to sign your commit. <br> 
Don't forget to do ```export GPG_TTY=$(tty)``` to sign the commit. <br>

# Logger 
The logger is setting to write logs on ```/var/log/api_c.log```.<br>