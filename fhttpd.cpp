//cl fhttpd.cpp /link ws2_32.lib mswsock.lib
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

WSADATA wsaData;
WORD version;
const size_t tz_len = 4;
char timezone[tz_len];

const int US_ENGLISH = 0x409;

std::set<char> otherallowedchars;

struct caseless_cmp_t
{
	bool operator() (const std::wstring &l, const std::wstring &r)
	{
		return _wcsicmp(l.c_str(), r.c_str()) < 0;
	}
};

typedef std::map<std::wstring, std::wstring, caseless_cmp_t> hashes_t;
hashes_t hashes;

int send(IN SOCKET s, __in_bcount(len) const char FAR * buf, IN size_t len, IN int flags)
{
	if (len > size_t(std::numeric_limits<int>().max()))
		throw std::invalid_argument("too much send");
	return send(s, buf, (int)len, flags);
}

bool isalphahex(const char c)
{
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

unsigned __int64 filesize(DWORD h, DWORD l)
{
	return (((unsigned __int64)h << 32)) + l;
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
			ss << L"&quot;";
		else if (*it == L'"')
			ss << L"&#039;";
		else
			ss << *it;
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

// Thu, 27 Nov 2008 19:25:08 GMT
std::ostream &daterfc1123(std::ostream &os, const SYSTEMTIME *time = NULL)
{
	char buf[MAX_PATH];
	GetDateFormatA(US_ENGLISH, 0, time, "ddd',' dd MMM yyyy ", &buf[0], MAX_PATH);
	os << buf;
	GetTimeFormatA(US_ENGLISH, 0, time, "HH':'mm':'ss ", &buf[0], MAX_PATH);
	os << buf << timezone;
	return os;
}

void send_base_headers(SOCKET client, const int code = 200)
{
	std::stringstream resp;
	resp << "HTTP/1.1 " << code << "\r\nServer: fhttpd 0.00\r\nDate: ";
	daterfc1123(resp);
	resp << "\r\n";
	const std::string ra = resp.str();
	send(client, ra.c_str(), ra.size(), 0);
}

void send_end_headers(SOCKET client)
{
	send(client, "\r\n", 2, 0);
}

std::wstring link_to(const std::wstring &s, const bool dir = false)
{
	const std::wstring safeurl = htmlspecialchars(s);
	return L"<a href=\"" + safeurl + (dir ? L"/" : L"") + L"\">" + safeurl + L"</a>";
}

void xml_index_page_footer(SOCKET client)
{
	send(client, "</FileListing>\r\n");
}

void xml_head(SOCKET client, const std::wstring &url)
{
	send_base_headers(client);
	send(client, "Content-Type: application/xml; charset=utf-8\r\n");
	send_end_headers(client);
	send(client, "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n"
		"<?xml-stylesheet type=\"text/xsl\" href=\"/index.xsl\"?>\r\n"
		"<FileListing Version=\"1\" CID=\"ponies\" Base=\"");
	send(client, htmlspecialchars(url));
	send(client, "\" Generator=\"fhttpd 0.0\">\r\n");

}

void xml_index_page(SOCKET client, const std::wstring &url, const std::wstring &path)
{
	WIN32_FIND_DATA findd;
	HANDLE h = FindFirstFile((path + L"*").c_str(), &findd);
	if (h == INVALID_HANDLE_VALUE)
		throw std::invalid_argument("find failed");

	xml_head(client, url);

	do
	{
		if (findd.cFileName[0] == L'.' && (findd.cFileName[1] == 0 || (findd.cFileName[1] == L'.' && findd.cFileName[2] == 0)))
			continue;
		std::wstringstream wss;
		const bool dir = (findd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY;
		if (dir)
			wss << L"\t<Directory";
		else
			wss << L"\t<File";
		wss << L" Name=\"" << htmlspecialchars(findd.cFileName) << L"\"";
		if (!dir)
		{
			wss << L" Size=\"" << filesize(findd.nFileSizeHigh, findd.nFileSizeLow) << L"\"";
			const std::wstring search = path + findd.cFileName;
			const hashes_t::const_iterator it = hashes.find(search);
			if (it != hashes.end())
				wss << L" TTH=\"" << it->second << "\"";
		}
		
		wss << L"/>\r\n";
		send(client, wss.str());
	}
	while (FindNextFile(h, &findd));
	xml_index_page_footer(client);
}

void index_page(SOCKET client, const mountmap_t &mounted)
{
	xml_head(client, L"/");
	for (mountmap_t::const_iterator it = mounted.begin(); it != mounted.end(); ++it)
		send(client, L"\t<Directory Name=\"" + htmlspecialchars(it->first) + L"/\"/>\r\n");
	xml_index_page_footer(client);
}


void error_page(SOCKET client, const int code, const char *msg)
{
	send_base_headers(client, code);
	send_end_headers(client);
	send(client, msg);
}

void xsl(SOCKET client)
{
	send_base_headers(client);
	send(client, "Content-type: application/xml; charset=utf-8\r\n");
	send_end_headers(client);
	send(client, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
		"<xsl:stylesheet version=\"1.0\"\r\n"
		"xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\r\n"
		"<xsl:template match=\"/\">\r\n"
		"  <html>\r\n"
		"    <head><style type=\"text/css\">td { padding: .5ex }</style></head>\r\n"
		"  <body>\r\n"
		"    <table border=\"1\">\r\n"
		"    <tr bgcolor=\"#9acd32\">\r\n"
		"      <th>Name</th><th>Size</th>\r\n"
		"    </tr>\r\n"
		"    <xsl:for-each select=\"FileListing/*\">\r\n"
		"    <tr>\r\n"
		"      <td><xsl:element name=\"a\"><xsl:attribute name=\"href\"><xsl:value-of select=\"@Name\"/></xsl:attribute><xsl:value-of select=\"@Name\"/></xsl:element></td>\r\n"
		"      <td style=\"text-align: right\"><xsl:call-template name=\"format-bytes\"><xsl:with-param name=\"bytes_cnt\" select=\"@Size\"/></xsl:call-template></td>\r\n"
		"    </tr>\r\n"
		"    </xsl:for-each>\r\n"
		"    </table>\r\n"
		"  </body>\r\n"
		"  </html>\r\n"
		"</xsl:template>\r\n"
		"<xsl:variable name=\"Mega\" select=\"1024 * 1024\"/>\r\n"
		"<xsl:variable name=\"Giga\" select=\"1024 * $Mega\"/>\r\n"
		"\r\n"
		"<xsl:template name=\"format-bytes\">\r\n"
		"<xsl:param name=\"cnt_bytes\" select=\"@Size\"/>\r\n"
		"<xsl:choose>\r\n"
		"        <xsl:when test=\"$cnt_bytes &lt; 1024\"><xsl:value-of select=\"format-number($cnt_bytes, '#,##0')\"/> bytes</xsl:when>\r\n"
		"        <xsl:when test=\"$cnt_bytes &lt; $Mega\"><xsl:value-of select=\"format-number($cnt_bytes div 1024, '#,###.#')\"/>kb</xsl:when>\r\n"
		"        <xsl:when test=\"$cnt_bytes &lt; $Giga\"><xsl:value-of select=\"format-number($cnt_bytes div $Mega, '#,###.#')\"/>mb</xsl:when>\r\n"
		"        <xsl:when test=\"$cnt_bytes\"><xsl:value-of select=\"format-number($cnt_bytes div $Giga, '#,###.#')\"/>gb</xsl:when>\r\n"
		"        <xsl:otherwise><xsl:text>&#160;</xsl:text></xsl:otherwise>\r\n"
		"</xsl:choose>\r\n"
		"</xsl:template>\r\n"


		"</xsl:stylesheet>\r\n");
}

struct httpexception : std::exception
{
	httpexception(int code, const std::string &msg) : code(code), std::exception(msg.c_str())
	{
	}

	const int code;
};

struct win32exception : std::exception
{
	win32exception(const std::string &msg, DWORD err = GetLastError()) : err(err), std::exception(msg.c_str())
	{
	}



	const char *what() const
	{
		if (!what_.empty())
			return what_.c_str();
		std::stringstream out;
		LPWSTR lpMsgBuf = NULL;

		out << "Win32 error during '" << std::exception::what() << "': ";
		
		if (FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			err,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL ))
			out << err << ": " << utf8encode(std::wstring(lpMsgBuf));
		else
			out << " (FormatMessage failed: " << GetLastError() << ")";

		LocalFree(lpMsgBuf);

		what_ = out.str();
		return what_.c_str();
	}

	const DWORD err;
	private: mutable std::string what_;
};

struct winsockexception : std::exception
{
	winsockexception(const std::string &msg, int err = WSAGetLastError()) : err(err), std::exception(msg.c_str())
	{
	}

	const int err;
};

int main()
{
	std::clog << "Starting.. " << std::endl;
	TIME_ZONE_INFORMATION tz;
	GetTimeZoneInformation(&tz);
	size_t out;
	wcstombs_s(&out, timezone, tz_len, tz.StandardName, _TRUNCATE);
	timezone[tz_len - 1] = 0;

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


	typedef std::map<std::wstring, std::wstring> wwmap;
	wwmap mounted;
	mounted[L"music"] = L"q:\\music\\";
	mounted[L"films"] = L"r:\\films\\";

	FILE *file;
	errno_t err;
	if ((err = fopen_s(&file, "c:/dc++/hashindex.xml", "rb")) != 0)
	{
		char buf[MAX_PATH];
		std::clog << "Couldn't open hashindex";
		if (strerror_s(buf, MAX_PATH, err) == 0)
			std::clog << ": " << buf;
		std::clog << ".  Hash loading skipped." << std::endl;
	}
	else
	{
		std::clog << "Opened hash index... ";

		fseek(file, 0, SEEK_END);
		const std::wistream::streamoff len = ftell(file);
		fseek(file, 0, SEEK_SET);


		char *fil = new char[len];
		//fi.read(fil, len);
		fread(fil, 1, len, file);
		
		for (std::wistream::streamoff i = 0; i < len - 32; ++i)
		{
			if (fil[i] == L'\n' && fil[i+4] == L'F')
			{
				const std::wstring line = utf8decode(std::string(&fil[i+1], std::find(&fil[i+1], &fil[len-1], '\n')-&fil[i+1]));

				const std::wstring::size_type hashpos = line.find(L" Root=\"") + 7;
				const std::wstring path = line.substr(14, line.find_first_of(L'"', 15)-14);
				for (wwmap::const_iterator oot = mounted.begin(); oot != mounted.end(); ++oot)
					if (std::equal(oot->second.begin(), oot->second.end(), path.begin()))
						hashes[path] = line.substr(hashpos, 39);
			}
			if (i % 10000000 == 0)
				std::clog << static_cast<int>(i/(float)len*100) << "%.. ";
		}

		delete []fil;
	}

	std::clog << std::endl << "Setting up connection..." << std::endl;

	version = MAKEWORD( 2, 0 );

	if ( WSAStartup( version, &wsaData ) != 0 )
	    return FALSE;

	if ( LOBYTE( wsaData.wVersion ) != 2 ||
	     HIBYTE( wsaData.wVersion ) != 0 )
	{
	    WSACleanup();
	    return FALSE;
	}

	SOCKET server;
	server = socket( AF_INET, SOCK_STREAM, 0 );

	struct sockaddr_in sin;
	memset( &sin, 0, sizeof sin );
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	u_short port = 8001;
	sin.sin_port = htons( port );

	while ( bind( server, (const sockaddr *)&sin, sizeof sin ) == SOCKET_ERROR )
	{
		std::cout << port << " not available, trying next." << std::endl;
		sin.sin_port = htons( ++port );
	}

	while ( listen( server, SOMAXCONN ) == SOCKET_ERROR );

	SOCKET client;
	int length;

	std::clog << "Ready." << std::endl;

	while (
		length = sizeof sin,
		(client = accept( server, (sockaddr *)&sin, &length )) != INVALID_SOCKET)
	{
		try
		{
			std::stringstream ss;
			{
				const size_t block_sz = 0x3FFF;
				char block[block_sz];
				
				int red;
				do
				{
					red = recv(client, block, block_sz, 0);
					if (red == SOCKET_ERROR)
						break; // XXX TODO
					block[red] = 0;
					ss << block;
				}
				while(red == block_sz);
			}

			std::string line;
			if (!std::getline(ss, line))
				throw httpexception(400, "not a request at all?");

			if (line.substr(0, 4) != "GET ")
				throw httpexception(501, "not a GET request");

			std::string url;

			std::getline(std::stringstream(line.substr(4)), url, ' ');
			std::wstring wurl = unurl(url);
			validate_pathname(wurl);
			if (wurl[0] != '/')
				throw std::invalid_argument("no preceding slash");

			if (line.substr(5 + url.size()).substr(0,7)  != "HTTP/1.")
				throw std::invalid_argument("not HTTP/1.");

			if (wurl.length() == 1)
				index_page(client, mounted);
			else
			{
				std::wstring::size_type fs = wurl.find(L"/", 1);
				if (fs == std::wstring::npos || wurl.length() == fs + 1)
				{
					std::wstring mountpoint = wurl.substr(1, fs-1);
					if (mountpoint == L"index.xsl")
						xsl(client);
					else if (mounted.find(mountpoint) != mounted.end())
						xml_index_page(client, wurl, mounted[mountpoint]);
					else
						error_page(client, 404, "not a mountpoint");
				} else {
					const std::wstring file = url2path(wurl, mounted);

					DWORD attribs = GetFileAttributes(file.c_str());
					if (attribs == INVALID_FILE_ATTRIBUTES)
					{
						WIN32_FIND_DATA findd;
						if (FindFirstFile(file.c_str(), &findd) == INVALID_HANDLE_VALUE)
							throw httpexception(404, "file doesn't exist");
						else
							throw httpexception(500, "can't get attributes, don't know why");
					}

					if ((attribs & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY)
						if (*--wurl.end() == L'/')
							xml_index_page(client, wurl, file);
						else
						{
							send_base_headers(client, 301); // moved perm
							send(client, L"Location: " + wurl + L'/');
							send_end_headers(client);
						}
					else
					{
						HANDLE h = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
						if (h == INVALID_HANDLE_VALUE)
						{
							const DWORD err = GetLastError();
							if (err == ERROR_FILE_NOT_FOUND)
								throw httpexception(404, "not found");
							else if (err == ERROR_ACCESS_DENIED)
								throw httpexception(403, "access denied");
							else
								throw httpexception(500, "can't open file, don't know why");
						}
						else
						{
							BY_HANDLE_FILE_INFORMATION bhfi;
							if (!GetFileInformationByHandle(h, &bhfi))
								throw httpexception(404, "apparently not a file");

							unsigned __int64 file_remaining = filesize(bhfi.nFileSizeHigh, bhfi.nFileSizeLow);
							send_base_headers(client);
							std::stringstream resp;
							SYSTEMTIME lmd;
							resp << "Accept-Ranges: none\r\nConnection: Close\r\nLast-Modified: ";
							if (!FileTimeToSystemTime(&bhfi.ftLastWriteTime, &lmd))
								throw win32exception("FileTimeToSystemTime failed");
							daterfc1123(resp, &lmd);
							resp << "\r\nContent-Length: " << file_remaining;
							resp << "\r\n\r\n";

							send(client, resp.str().c_str(), resp.str().size(), 0);

							//const DWORD block_size = 0x7fffffff;
							const DWORD block_size = 1024 * 1024 * 10;

							while (file_remaining > 0)
							{
								DWORD to_transmit = DWORD(file_remaining > block_size ? block_size : file_remaining);
								file_remaining -= to_transmit;
								if (!TransmitFile(client, h, to_transmit, 0, NULL, NULL, 0))
									throw winsockexception("TransmitFile");
							}
						}
					}
				}
			}
		}
		catch (win32exception &e)
		{
			const char *msg = e.what();
			std::clog << "win32 error: " << msg << std::endl;
			error_page(client, 500, msg);
		}
		catch (httpexception &e)
		{
			error_page(client, e.code, e.what());
		}
		catch (std::exception &e)
		{
			std::clog << e.what() << std::endl;
		}
		shutdown(client, SD_SEND);
		closesocket(client);
	}
	WSACleanup();
}
