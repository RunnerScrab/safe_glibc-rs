#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int get_file_size(FILE* pFile)
{
	fseek(pFile, 0, SEEK_END);
	unsigned int size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	return size;
}

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		printf("Need filename, and start + end offsets.\n");
		return 0;
	}
	const char* filename = argv[1];
	FILE* pFile = 0;
	pFile = fopen(filename, "rb");

	if(!pFile)
	{
		printf("Error opening file.\n");
		return 0;
	}
	unsigned int filelen = get_file_size(pFile);
	char* pFileBuffer = (char*) malloc(filelen);
	if(!pFileBuffer)
	{
		fclose(pFile);
		printf("Failed to allocate buffer.\n");
		return 0;
	}
	size_t bytes_read = fread((void*) pFileBuffer, 1, filelen, pFile);
	for(; bytes_read < filelen;)
	{
		size_t bread = fread(&pFileBuffer[bytes_read], 1, filelen - bytes_read, pFile);
		bytes_read += bread;
	}
	size_t start = argc > 2 ? atoi(argv[2]) : 0;
	size_t end = argc > 3 ? atoi(argv[3]) : filelen;
	printf("Start: %d End: %d file len: %d\n", start, end, filelen);
	size_t idx = 0;
	char* pOutputBuf = (char*) malloc(filelen * 7);
	memset(pOutputBuf, 0, filelen * 7);
	size_t bytes_written = 0;
	int bytesput = 1;
	for(idx = start; idx < end; ++idx, ++bytesput)
	{
		char buf[64] = {0};
		int bwritten = sprintf(buf, "0x%.2x%s", 
					(unsigned char) pFileBuffer[idx] & 255,
					idx < (filelen - 1) ? "," : "\n");
		strcat(pOutputBuf, buf);
		if(bytesput == 13)
		{
			bwritten += 1;
			strcat(pOutputBuf, "\n");
			bytesput = 0;
		}
		bytes_written += bwritten;
	}
	printf("%d bytes written.\n", bytes_written);
	char outfilename[64] = {0};
	sprintf(outfilename, "%s.txt", filename);
	FILE* pOutFile = fopen(outfilename, "w");
	fwrite(pOutputBuf, 1, bytes_written, pOutFile);

	free(pOutputBuf);
	free(pFileBuffer);
	fclose(pOutFile);
	fclose(pFile);
	return 0;	
}
