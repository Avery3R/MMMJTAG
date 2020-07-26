#include <MMMJTAG.h>

int main(int argc, char** argv)
{
	JTAGConnect();

	HANDLE hKernel = JTAGOpenKernel();

	JTAGRun();

	return 0;
}