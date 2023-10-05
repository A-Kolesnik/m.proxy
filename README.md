MITM Proxy (TLS)
---
1. config.h   
- Изменить пути к сертификату и секретному ключу CA   
- Изменить (при необходимости) пути к хранилищу сертификатов (каталог + файл)   
2. Выданный клиенту LAN сертификат валиден 1 год  
3. Выданный клиенту сертификат НЕ мультидоменный  
4. Сообщение ClientHello обязательно должно содержать расширение SNI. В противном случае,  
соединение не будет установлено  
5. Перед началом работы необходимо установить OpenSSL. Для Ubuntu необходимо  
запустить скрипт openssl_install:  
```
openssl_install - Запустить без обновления репозитория  
openssl_install <любой символ> - Запустить с обновлением репозитория

```
6. При инициализации модуля MitmProxy:  
```C++

#include "proxy.h"

if(!secure_proxy::Init()){
	//Загрузка модуля не может быть продолжена
}

```
7. Для каждого соединения необходимо создать экземпляр класса <b>secure_proxy::Proxy</b>:  
```C++

secure_proxy::Proxy proxy{};

if (!proxy.Load()) { 
	//Не удалось загрузить компоненты сервера или клиента    
}

```

8. Обработка сообщения от клиента LAN  
```C++

auto status = proxy.ProcessLANClientMessage(buffer, buffer_size);

if(!status){
	// Не удалось обработать сообщение клиента
}
```
9. Обработка сообщения от сервера WAN  
```C++
auto status = proxy.ProcessWANServerMessage(buffer, buffer_size);
```
10. После обработки порции данных клиента LAN / сервера WAN, необходимо выполнить  
проверку наличия данных - ответа на сообщения от Proxy  
```C++
if (proxy.client_.HasReadData()) {
	auto status = proxy.client_.ReadData(write_buffer, write_buffer_size, readed);
	// Коды возврата описаны в документации к методу
}

if (proxy.server_.HasReadData()) {
	auto status = proxy.server_.ReadData(write_buffer, write_buffer_size, readed);
	// Коды возврата описаны в документации к методу
}
```

