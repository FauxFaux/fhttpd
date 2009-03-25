#pragma once

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

	win32exception(const std::wstring &msg, DWORD err = GetLastError()) : err(err), std::exception(utf8encode(msg).c_str())
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

struct winsockexception : win32exception
{
	winsockexception(const std::string &msg, int err = WSAGetLastError()) : win32exception(msg.c_str(), err)
	{
	}
};
