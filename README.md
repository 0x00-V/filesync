
### Compile:
```
g++ -std=c++20 main.cpp -lssl -lcrypto -o filesync
```


Compile on my system:
```
g++ -std=c++20 main.cpp \
   -I/opt/homebrew/opt/openssl@3/include \
   -L/opt/homebrew/opt/openssl@3/lib \
   -lssl -lcrypto \
   -o filesync
```
