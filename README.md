MITM Proxy (TLS)
---
1. config.h   
- �������� ���� � ����������� � ���������� ����� CA   
- �������� (��� �������������) ���� � ��������� ������������ (������� + ����)   
2. �������� ������� LAN ���������� ������� 1 ���  
3. �������� ������� ���������� �� ��������������  
4. ��������� ClientHello ����������� ������ ��������� ���������� SNI. � ��������� ������,  
���������� �� ����� �����������  
5. ����� ������� ������ ���������� ���������� OpenSSL. ��� Ubuntu ����������  
��������� ������ openssl_install:  
```
openssl_install - ��������� ��� ���������� �����������  
openssl_install <����� ������> - ��������� � ����������� �����������

```
6. ��� ������������� ������ MitmProxy:  
```C++

#include "proxy.h"

if(!secure_proxy::Init()){
	//�������� ������ �� ����� ���� ����������
}

```
7. ��� ������� ���������� ���������� ������� ��������� ������ <b>secure_proxy::Proxy</b>:  
```C++

secure_proxy::Proxy proxy{};

if (!proxy.Load()) { 
	//�� ������� ��������� ���������� ������� ��� �������    
}

```

8. ��������� ��������� �� ������� LAN  
```C++

auto status = proxy.ProcessLANClientMessage(buffer, buffer_size);

if(!status){
	// �� ������� ���������� ��������� �������
}
```
9. ��������� ��������� �� ������� WAN  
```C++
auto status = proxy.ProcessWANServerMessage(buffer, buffer_size);
```
10. ����� ��������� ������ ������ ������� LAN / ������� WAN, ���������� ���������  
�������� ������� ������ - ������ �� ��������� �� Proxy  
```C++
if (proxy.client_.HasReadData()) {
	auto status = proxy.client_.ReadData(write_buffer, write_buffer_size, readed);
	// ���� �������� ������� � ������������ � ������
}

if (proxy.server_.HasReadData()) {
	auto status = proxy.server_.ReadData(write_buffer, write_buffer_size, readed);
	// ���� �������� ������� � ������������ � ������
}
```

