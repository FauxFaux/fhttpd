#define NOMINMAX
#define _CRT_SECURE_CPP_OVERLOAD_SECURE_NAMES 1
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <sstream>
#include <limits>
#include <iostream>
#include <set>
#include <cassert>
#include <map>
#include <iomanip>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <clocale>

#include "util.h"

std::set<char> otherallowedchars;

int send(IN SOCKET s, __in_bcount(len) const char FAR * buf, IN size_t len, IN int flags)
{
	if (len > size_t(std::numeric_limits<int>().max()))
		throw std::invalid_argument("too much send");
	return send(s, buf, (int)len, flags);
}

bool starts_with(const std::wstring &s, const std::wstring &what)
{
	return s.size() >= what.size() && std::equal(what.begin(), what.end(), s.begin());
}

bool isalphahex(const char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

filesize_t filesize(DWORD h, DWORD l)
{
	return (((filesize_t)h << 32)) + l;
}

char alphahex(const char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';

	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;

	throw std::invalid_argument("not hex");
}

std::wstring utf8decode(const std::string &s)
{
	wchar_t *buf = new wchar_t[(int)s.size()];
	int ret = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.c_str(), (int)s.size(), buf, (int)s.size());
	std::wstring q(buf, ret);
	delete[] buf;
	return q;
}

std::string utf8encode(const std::wstring &s)
{
	int outbits = (int)s.size() * 5;
	char *buf = new char[outbits];
	outbits = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), buf, outbits, NULL, NULL);
	std::string q(buf, outbits);
	delete[] buf;
	return q;
}

bool urlallowedchar(char c)
{
	if (otherallowedchars.empty())
	{
		otherallowedchars.insert('-');
		otherallowedchars.insert('_');
		otherallowedchars.insert('.');
		otherallowedchars.insert('~');
		otherallowedchars.insert('!');
		otherallowedchars.insert('*');
		otherallowedchars.insert('\'');
		otherallowedchars.insert('(');
		otherallowedchars.insert(')');
		otherallowedchars.insert(';');
		otherallowedchars.insert(':');
		otherallowedchars.insert('@');
		otherallowedchars.insert('=');
		otherallowedchars.insert('+');
		otherallowedchars.insert('$');
		otherallowedchars.insert(',');
		otherallowedchars.insert('/');
		otherallowedchars.insert('#');
		otherallowedchars.insert('[');
		otherallowedchars.insert(']');
		otherallowedchars.insert('&');
		//?
		otherallowedchars.insert('{');
		otherallowedchars.insert('}');
		// Specifically not included: ? (end), # (end), % (handled)
	}

	return (c >= 'a' && c <= 'z') 
			|| (c >= 'A' && c <= 'Z')
			|| (c >= '0' && c <= '9')
			|| otherallowedchars.find(c) != otherallowedchars.end();
}

std::wstring unurl(const std::string &s)
{
	bool firsthex = false;
	char secondhex = -1;
	std::stringstream ss;
	for (std::string::const_iterator it = s.begin(); it != s.end(); ++it)
		if (*it == '?' || *it == '#' || *it == '\0')
			break;
		else if (!firsthex && secondhex == -1 && *it == '%')
			firsthex = true;
		else if (firsthex && isalphahex(*it))
		{
			secondhex = alphahex(*it);
			firsthex = false;
		}
		else if (secondhex != -1 && isalphahex(*it))
		{
			ss << (char)((secondhex << 4) + alphahex(*it));
			secondhex = -1;
		}
		else if (urlallowedchar(*it))
			ss << *it;
		else
			throw std::invalid_argument("undecodable url");
	return utf8decode(ss.str());
}

std::string urlize(const std::wstring &ws)
{
	const std::string s = utf8encode(ws);
	std::stringstream ss;
	for (std::string::const_iterator it = s.begin(); it != s.end(); ++it)
		if (urlallowedchar(*it))
			ss << *it;
		else
			ss << "%" << std::setfill('0') << std::hex << (int)(unsigned char)*it;
	return ss.str();
}

std::wstring htmlspecialchars(const std::wstring &ws)
{
	std::wstringstream ss;
	for (std::wstring::const_iterator it = ws.begin(); it != ws.end(); ++it)
		if (*it == L'&')
			ss << L"&amp;";
		else if (*it == L'<')
			ss << L"&lt;";
		else if (*it == L'>')
			ss << L"&gt;";
		else if (*it == L'\'')
			ss << L"&apos;";
		else if (*it == L'"')
			ss << L"&quot;";
		else
			ss << *it;
	return ss.str();
}

std::wstring htmlspecialchars_decode(const std::wstring &ws)
{
	std::wstringstream ss;
	std::wstring::const_iterator it = ws.begin(), prev = ws.begin();
	while ((it = std::find(it, ws.end(), L'&')) != ws.end())
	{
		ss << std::wstring(prev, it);
		std::wstring::const_iterator semi = std::find(it, ws.end(), L';');
		if (semi == ws.end())
			throw std::invalid_argument("no semi");
		++it;
		const std::wstring token(it, semi);
		if (token == L"amp")
			ss << L"&";
		else if (token == L"lt")
			ss << L"<";
		else if (token == L"gt")
			ss << L">";
		else if (token == L"quot")
			ss << L"\"";
		else if (token == L"apos")
			ss << L"'";
		else if (starts_with(token, L"#"))
		{
			wchar_t code;
			std::wstringstream hash(token);
			hash.ignore();
			if (hash.peek() == L'x')
				hash.ignore() >> std::hex >> (short&)code;
			else
				hash >> (short&)code;
			ss << static_cast<wchar_t>(code);
		}
		else
			throw std::invalid_argument("unknown ent");

		it = ++semi;
		prev = it;
	}
	ss << std::wstring(prev, ws.end());
	return ss.str();
}

void validate_pathname(const std::wstring &wurl)
{
	if (wurl.find(L"..") != std::wstring::npos)
		throw new std::invalid_argument("no relative paths");

	for (std::wstring::const_iterator it = wurl.begin(); it != wurl.end(); ++it)
		if (*it == 0 || *it == '\\' || *it == '<' || *it == '>' || *it == ':' || *it == '|' || *it == '?' || *it == '*')
			throw std::invalid_argument("illegal path chars");
}

std::wstring forward2back(std::wstring w)
{
	std::replace(w.begin(), w.end(), '/', '\\');
	return w;
}

typedef std::map<std::wstring, std::wstring> mountmap_t;
std::wstring url2path(const std::wstring &wurl, const mountmap_t &mounted)
{
	std::wstring::size_type fs = wurl.find(L"/", 1);

	std::wstring mountpoint = wurl.substr(1, fs-1);
	mountmap_t::const_iterator it;
	if ((it = mounted.find(mountpoint)) != mounted.end())
		return it->second + forward2back(wurl.substr(fs));

	throw std::invalid_argument("not a mountpoint");
}

int send(SOCKET client, const std::wstring &s)
{
	const std::string by = utf8encode(s);
	return send(client, by.c_str(), by.size(), 0);
}

int send(SOCKET client, const std::string &s)
{
	return send(client, s.c_str(), s.size(), 0);
}
