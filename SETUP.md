## DEBIAN NEO4J SETUP
### Purpose
This documentation will outline the process of installing Neo4J and setting up a development environment for `Awesome-Iguanas`.

### OS Stack:
> 1. Windows 10/11 
> 2. [Debian 12](https://www.debian.org)
> 3. [Oracle VirtualBox](https://www.oracle.com/virtualization/technologies/vm/downloads/virtualbox-downloads.html)

## Debian Installation
Create a new `VirtualBox` instance for `Debian 12`. 
> Notes: Ensure that the <b><i>Unattended Install</i></b> setting has a username and password set.
>        Take note of this username and password for later.

Additionally, we want to set up the ports for `Debian 12`.
> <i>Settings -> Expert -> Network -> Port Forwarding</i> 

| Name          | Protocol | Host IP | Host Port | Guest IP | Guest Port |
|:--------------|:---------|:--------|:----------|:---------|:-----------|
| Neo-Server    | TCP      |         | 7687      |          | 7687       |
| Neo4J         | TCP      |         | 7474      |          | 7474       |
| SSH           | TCP      |         | 2222      |          | 2222       |

## Installing JDK21, Neo4J, and openssh-server 
Start up `Debian 12` and begin the installation process.

Once you've completed the startup open the `Terminal` application and log in as the root user using the `su` command.

To install the Java 21 dependency run the following commands:

> wget https://download.oracle.com/java/21/latest/jdk-21_linux-x64_bin.deb  
> sudo dpkg -i jdk-21_linux-x64_bin.deb  
> sudo apt install jdk-21_linux-x64_bin.deb  

To install Neo4J run the following commands:

> wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/neotechnology.gpg  
> echo 'deb [signed-by=/etc/apt/keyrings/neotechnology.gpg] https://debian.neo4j.com stable latest' | sudo tee -a /etc/apt/sources.list.d/neo4j.list  
> sudo apt-get update  
> sudo apt-get install neo4j  

To install openssh-server run the following commands (since Debian does not use SSH by default):

> sudo apt install openssh-server  
> sudo systemctl enable ssh  
> sudo systemctl start ssh

## SSH into Debian from Windows
Start up `cmd` in your `Windows OS` 

You can now ssh into `Debian 12` using this command:

> ssh -L 7474:localhost:7474 -L 7687:localhost:7687 -p 2222 (debian username)@127.0.0.1

Your password will be the password you created for `Debian 12`

To exit the secure shell simply run the <i>exit</i> command.

## Restarting
When restarting the SSH you'll want to run the following commands in `Debian 12`:

> sudo systemctl enable ssh
> sudo systemctl start ssh
> neo4j start

Then run the set-up from the previous section.

## Node.js
In order to run the instance of `Neo4J` we're going to need to make some changes to Repository.

On your `Windows OS` download [Node.js](https://nodejs.org/en).

Clone the repository to an IDE of your choosing.

In that cloned repository create an `.env` file with these contents:

> VITE_NEO4J_URI=bolt://localhost:(port)
> VITE_NEO4J_USER=(user)
> VITE_NEO4J_PASSWORD=(password)

Then install npm on the IDE Terminal using these commands:

> npm install
> npm run dev

This will open the development server for `Neo4J` the credentials are as follows:

> user: neo4j
> password: neo4j

Change the password as you see fit and your development server is set up.




