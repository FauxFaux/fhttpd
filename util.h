#pragma once

typedef LONGLONG filesize_t;

bool isalphahex(const char c);
filesize_t filesize(DWORD h, DWORD l);
char alphahex(const char c);
std::wstring utf8decode(const std::string &s);
std::string utf8encode(const std::wstring &s);
bool urlallowedchar(char c);
std::wstring unurl(const std::string &s);
std::string urlize(const std::wstring &ws);
std::wstring htmlspecialchars(const std::wstring &ws);
std::wstring htmlspecialchars_decode(const std::wstring &ws);
void validate_pathname(const std::wstring &wurl);
std::wstring forward2back(std::wstring w);

bool starts_with(const std::wstring &s, const std::wstring &what);

typedef std::map<std::wstring, std::wstring> mountmap_t;
std::wstring url2path(const std::wstring &wurl, const mountmap_t &mounted);

int send(IN SOCKET s, __in_bcount(len) const char FAR * buf, IN size_t len, IN int flags);
int send(SOCKET client, const std::wstring &s);
int send(SOCKET client, const std::string &s);

#define RANGE(x) (x).begin(), (x).end()
