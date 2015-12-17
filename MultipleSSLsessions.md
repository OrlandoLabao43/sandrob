# Introduction #

SSL session is bound to hostname:port

# Details #

SSL contexts are stored in dictionary.

Key is hostname:port


Because android caches connections the same way,

SandroB cannot have finer separation.


Same ssl context will be used for


https://hostname:port/secure_dir1 and


https://hostname:port/secure_dir2