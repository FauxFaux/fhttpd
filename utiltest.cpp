#include "stdafx.h"
#include "util.h"

struct assertion_exception
{
	std::string s;
	assertion_exception() {}
	assertion_exception(const std::string &s) : s(s) {}
	const char *what() { return s.c_str(); }
};

#define fail() throw assertion_exception();
#undef assert
#define assert(x) if (!(x)) throw assertion_exception();
#define assert_equals(x, y) if ((x) != (y)) throw assertion_exception(utf8encode(L"Expected " + (x + (L", got " + y))));



#define do_test(x) \
	try { test##x(); ++passes; } \
	catch (assertion_exception &e) { ++fails; std::cout << "WAAAAAAA" << e.what() << "n" << std::endl; } \
	catch (std::exception &e) { ++errors; std::cout << e.what() << std::endl; } \
	catch (...) { ++errors; std::cout << "General failure" << std::endl; }

void testhtmlspecialchars_decode_valid()
{
	assert_equals(L"&", htmlspecialchars_decode(L"&amp;"));
	assert_equals(L"pony&badger", htmlspecialchars_decode(L"pony&amp;badger"));
	assert_equals(L"pony&", htmlspecialchars_decode(L"pony&amp;"));
	assert_equals(L"&pony", htmlspecialchars_decode(L"&amp;pony"));
	assert_equals(L"&\"'<>", htmlspecialchars_decode(L"&amp;&quot;&apos;&lt;&gt;"));
}

void testhtmlspecialchars_decode_invalid()
{
	try
	{
		htmlspecialchars_decode(L"&amp");
		fail();
	}
	catch (std::invalid_argument &) {}

	try
	{
		htmlspecialchars_decode(L"&;");
		fail();
	}
	catch (std::invalid_argument &) {}

	try
	{
		htmlspecialchars_decode(L"&pony;");
		fail();
	}
	catch (std::invalid_argument &) {}
}

void testhtmlspecialchars_decode_nums()
{
	assert_equals(L"a", htmlspecialchars_decode(L"&#97;"));
	assert_equals(L"a", htmlspecialchars_decode(L"&#x61;"));
}

#ifdef _TEST
int main()
#else
int pony()
#endif
{
	typedef unsigned int uint;
	uint passes = 0, fails = 0, errors = 0;
	do_test(htmlspecialchars_decode_valid);
	do_test(htmlspecialchars_decode_invalid);
	do_test(htmlspecialchars_decode_nums);

	std::cout 
		<< (passes + fails + errors) << " tests, " 
		<< passes << " passed, " 
		<< fails << " failed, " 
		<< errors << " errored." 
		<< std::endl;
	std::cin.get();
	return 0;
}
