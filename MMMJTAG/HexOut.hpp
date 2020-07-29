#pragma once

#include <iomanip>

template<typename T, size_t WIDTH = 0>
class _hexout
{
	public:
	_hexout(const T val) :
		m_val(val)
	{
	}

	friend std::ostream& operator<<(std::ostream& os, const _hexout& ho)
	{
		os << std::hex << std::uppercase << std::setfill('0');
		if(WIDTH == 0)
		{
			os << std::setw(sizeof(T)*2);
		}
		else
		{
			os << std::setw(WIDTH);
		}
		os << ho.m_val;
		os << std::dec << std::nouppercase;
		return os;
	}

	friend std::wostream& operator<<(std::wostream& os, const _hexout& ho)
	{
		os << std::hex << std::uppercase << std::setfill(L'0');
		if(WIDTH == 0)
		{
			os << std::setw(sizeof(T)*2);
		}
		else
		{
			os << std::setw(WIDTH);
		}
		os << ho.m_val;
		os << std::dec << std::nouppercase;
		return os;
	}

	private:
	const T m_val;
};

template<typename T>
_hexout<T,0> hexout(const T val)
{
	return _hexout<T,0>(val);
}

template<size_t WIDTH, typename T>
_hexout<T,WIDTH> hexout(const T val)
{
	return _hexout<T,WIDTH>(val);
}