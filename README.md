# dns-relay-server
Implements a basic dns relay server

The server when running listen to the dns port 53 for incomming request. For each request it tries to resolve the domain name using the local cache.txt.
When the requested IP is not found locally it relay the request to an outside server.
