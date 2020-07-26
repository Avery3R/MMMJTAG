#include <MMMJTAG.h>

int main(int argc, char** argv)
{
	JTAGConnect();

	HANDLE hKernel = JTAGOpenKernel();

	return 0;
}