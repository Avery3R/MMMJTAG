#include <MMMJTAG.h>

int main(int argc, char** argv)
{
	JTAGConnect(JTAG_DMA_DEDICATED_CORE);

	HKERNEL hKernel = JTAGOpenKernel(0x1AD000); //My page table always seems to be at 1AD000...

	JTAGRun();

	return 0;
}