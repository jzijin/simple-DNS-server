objects = dns_server.o common.o hashtable.o array.o
cli = dns_client.o
all : server client
server : $(objects)
	cc -o server $(objects)
client : $(cli)
	cc -o client $(cli)
.PHONY : clean
clean:
	rm server $(objects) client $(cli)
