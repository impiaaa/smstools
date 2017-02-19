/*
 * wwdumpsnd 0.4 by hcs
 * dump audio from Wind Waker or Super Mario Sunshine
 * needs JaiInit.aaf and *.aw in current directory
 * (if Sunshine, the file is 'msound.aaf', from 'nintendo.szs',
 *  but you'll need to rename it :))
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

typedef signed short s16;

/* read big endian */
unsigned int read32(unsigned char * buf) {
	return (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3];
}
float readfloat(unsigned char * buf) {
	union {
		float f;
		unsigned int ui32;
	} x;
	x.ui32 = read32(buf);
	return x.f;
}
unsigned int read16(unsigned char * buf) {
	return (buf[0]<<8) | buf[1];
}

/* write little endian (for WAV) */
void write32le(int in, unsigned char * buf) {
	buf[0]=in&0xff;
	buf[1]=(in>>8)&0xff;
	buf[2]=(in>>16)&0xff;
	buf[3]=(in>>24)&0xff;
}
void write16le(int in, unsigned char * buf) {
	buf[0]=in&0xff;
	buf[1]=(in>>8)&0xff;
}

/* AFC decoder */

const short afccoef[] __attribute__ ((aligned (16))) = {
0x0000,0x0000,
0x0800,0x0000,
0x0000,0x0800,
0x0400,0x0400,
0x1000,0xF800,
0x0E00,0xFA00,
0x0C00,0xFC00,
0x1200,0xF600,
0x1068,0xF738,
0x12C0,0xF704,
0x1400,0xF400,
0x0800,0xF800,
0x0400,0xFC00,
0xFC00,0x0400,
0xFC00,0x0000,
0xF800,0x0000
};

enum SamplesSourceType
{
	// Samples stored in ARAM at a rate of 16 samples/5 bytes, AFC encoded
	SRC_AFC_LQ_FROM_ARAM = 5,
	// Samples stored in ARAM in PCM8 format
	SRC_PCM8_FROM_ARAM = 8,
	// Samples stored in ARAM at a rate of 16 samples/9 bytes, AFC encoded
	SRC_AFC_HQ_FROM_ARAM = 9,
	// Samples stored in ARAM in PCM16 format
	SRC_PCM16_FROM_ARAM = 16,
};

/* from Dolphin's "UCode_Zelda_ADPCM.cpp" */
void AFCdecodebuffer(const s16 *coef, const char *src, signed short *out, short *histp, short *hist2p, enum SamplesSourceType type)
{
	short nibbles[16] __attribute__ ((aligned (16)));
	short delta = 1 << ((*src >> 4) & 0xF);
	short idx = (*src & 0xF);
	src++;
	
	if (type == SRC_AFC_HQ_FROM_ARAM)
	{
		for (size_t i = 0; i < 16; i += 2)
		{
			nibbles[i + 0] = *src >> 4;
			nibbles[i + 1] = *src & 0xF;
			src++;
		}
		for (size_t i = 0; i < 16; i++) {
			if (nibbles[i] >= 8)
				nibbles[i] -= 16;
			nibbles[i] <<= 11;
		}
	}
	else if (type == SRC_AFC_LQ_FROM_ARAM)
	{
		// In Pikmin, Dolphin's engine sound is using AFC type 5, even though such a sound is hard
		// to compare, it seems like to sound exactly like a real GC
		// In Super Mario Sunshine, you can get such a sound by talking to/jumping on anyone
		for (size_t i = 0; i < 16; i += 4)
		{
			nibbles[i + 0] = (*src >> 6) & 3;
			nibbles[i + 1] = (*src >> 4) & 3;
			nibbles[i + 2] = (*src >> 2) & 3;
			nibbles[i + 3] = (*src >> 0) & 3;
			src++;
		}
		
		for (size_t i = 0; i < 16; i++)
		{
			// 0 -> 0x0000
			// 1 -> 0x2000
			// 2 -> 0xc000
			// 3 -> 0xe000
			if (nibbles[i] >= 2)
				nibbles[i] -= 4;
			nibbles[i] <<= 13;
		}
	}
	else
	{
		fprintf(stderr, "Invalid format %d\n", type);
		return;
	}
	
	short yn1 = *histp;
	short yn2 = *hist2p;
	for (size_t i = 0; i < 16; ++i)
	{
		int sample = delta * nibbles[i] +
			(int)yn1 * coef[idx * 2] +
			(int)yn2 * coef[idx * 2 + 1];
		sample >>= 11;
		if (sample > 0x7fff)
			sample = 0x7fff;
		if (sample < -0x8000)
			sample = -0x8000;
		out[i] = sample;
		yn2 = yn1;
		yn1 = (short)sample;
	}
	*histp = yn1;
	*hist2p = yn2;
}

unsigned char wavhead[] = {
	 'R',  'I',  'F',  'F', 0x00, 0x00, 0x00, 0x00,	 'W',  'A',  'V',  'E',
	//                                             compression    channels             sample rate
	 'f',  'm',  't',  ' ', 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,	0x00, 0x00, 0x00, 0x00,
	//           bytes/sec block align bits/sample
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00,
};

int writeWAVHead(FILE * outfile, const int total_size, const int srate, const int bytes_per_sample) {
	write32le(total_size-8,           wavhead+0x04);
	write32le(srate,                  wavhead+0x18);
	write32le(srate*bytes_per_sample, wavhead+0x1C);
	write16le(bytes_per_sample,       wavhead+0x20);
	write16le(bytes_per_sample*8,     wavhead+0x22);
	if (fwrite(wavhead,1,sizeof(wavhead),outfile)!=sizeof(wavhead)) return 1;
	return 0;
}

unsigned char datahead[] = {
	'd', 'a', 't', 'a', 0x00, 0x00, 0x00, 0x00
};

/* dump a WAV, decoding AFC */
/* return 0 on success, 1 on failure */
int dumpAFC(FILE * const infile, const int size, enum SamplesSourceType type, FILE * outfile) {
	char inbuf[9] __attribute__ ((aligned (16)));
	short outbuf[16] __attribute__ ((aligned (16)));
	int sizeToDo;
	int framesize;
	int datasize;
	short hist=0,hist2=0;
	
	framesize = (type==SRC_AFC_LQ_FROM_ARAM) ? 5 : 9;
	datasize = size/framesize*16*2;
	
	write32le(datasize,datahead+4);
	if (fwrite(datahead,1,sizeof(datahead),outfile)!=sizeof(datahead)) return 1;

	for (sizeToDo = 0; sizeToDo < size; sizeToDo += framesize) {
		if (fread(inbuf,1,framesize,infile) != framesize)
			return 2;

		AFCdecodebuffer((s16*)afccoef,inbuf,outbuf,&hist,&hist2,type);

		if (fwrite(outbuf,1,16*2,outfile) != 16*2)
			return 3;
	}

	return 0;
}

int dumpPCM(FILE * const infile, const int size, enum SamplesSourceType type, FILE * outfile) {
	char inbuf[4];
	char outbuf[4];
	int sizeleft;
	int framesize;
	
	framesize = (type==SRC_PCM8_FROM_ARAM) ? 1 : 2;

	write32le(size,datahead+4);
	if (fwrite(datahead,1,sizeof(datahead),outfile)!=sizeof(datahead)) return 1;
	
	for (sizeleft=size;sizeleft>=framesize;sizeleft-=framesize) {
		if (fread(inbuf,1,framesize,infile) != framesize)
			return 1;
		
		for (int i = 0; i < framesize; i++) {
			outbuf[framesize-i-1] = inbuf[i];
		}
		
		if (fwrite(outbuf,1,framesize,outfile) != framesize)
			return 1;
	}
	
	return 0;
}

unsigned char smplhead[] = {
	's', 'm', 'p', 'l', 60, 0, 0, 0,
	// manfctr     product
	0, 0, 0, 0, 0, 0, 0, 0,
	// smplper  unity note      tuning
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// smptefmt smpteoffset
	0, 0, 0, 0, 0, 0, 0, 0,
	// numloops   smpldata
	1, 0, 0, 0, 0, 0, 0, 0,
	// cueptid        type
	0, 0, 0, 0, 1, 0, 0, 0,
	//   start         end
	0, 0, 0, 0, 0, 0, 0, 0,
	// fraction play count
	0, 0, 0, 0, 0, 0, 0, 0
};

int writeSMPL(FILE * outfile, int srate, unsigned char root_key, int loop_start_sample, int loop_end_sample) {
	write32le(1000000000/srate,  smplhead+0x10);
	write32le(root_key,          smplhead+0x14);
	write32le(loop_start_sample, smplhead+0x2C+0x08);
	write32le(loop_end_sample,   smplhead+0x2C+0x0C);
	if (fwrite(smplhead,1,sizeof(smplhead),outfile)!=sizeof(smplhead)) return 1;
	return 0;
}

int verbose = 0;
char output_dir[256] = ".";
char *aw_dir;

int doaw(FILE *infile, const int offset, int dump) {
	FILE * awfile;
	int next_aw_offset;
	unsigned char buf[4];
	int aw_name;
	int table_offset;
	int wav_count;
	int i;
	char fname[113]={0};
	enum SamplesSourceType type;

	/* offset to list of wave table entry offsets */
	if (fread(buf,1,4,infile)!=4) return 1;
	aw_name = read32(buf) + offset;
	table_offset = aw_name+112;

	next_aw_offset = ftell(infile);
	if (next_aw_offset<0) return 2;

	if (fseek(infile,aw_name,SEEK_SET)<0) return 3;

	/* aw file name */
	if (fread(fname,1,112,infile)!=112) return 4;
	if (dump) {
		char inname[sizeof(fname)+6];
		snprintf(inname, sizeof(inname), "%s/%s", aw_dir, fname);
		awfile = fopen(inname,"rb");
		if (!awfile) {
			fprintf(stderr, "Couldn't open %s\n", inname);
			return 5;
		}
	}

	/* number of waves */
	if (fread(buf,1,4,infile)!=4) return 6;
	wav_count = read32(buf);

	if (verbose) {
		printf("aw=%s\n",fname);
		printf("table at %x, wav_count=%x\n",table_offset,wav_count);
	}

	// null out file extension
	char *extptr = strrchr(fname, '.');
	if (extptr != NULL) *extptr = '\0';

	if (verbose)
		printf("n\toffset\tsize\tsrate\ttype\troot\tstart\tend\tcount\n");
	
	for (i=0;i<wav_count;i++) {
		int wav_entry_offset;
		int afcoffset,afcsize,srate;
		unsigned char type_id, root_key;
		unsigned char type_unk0, type_unk3;
		char outname[128];
		int loop_start_sample, loop_end_sample, num_samples, unk0, unk1, unk2;

		if (fseek(infile,table_offset+4+i*4,SEEK_SET)<0) return 7;
		if (fread(buf,1,4,infile)!=4) return 8;
		wav_entry_offset = read32(buf)+offset;

		/* go to the entry */
		if (fseek(infile,wav_entry_offset,SEEK_SET)<0) return 9;

		/* contains AFC type:
		    0 = type 9 (9 byte frames, samples from nibbles)
		    1 = type 5 (5 byte frames, samples from half-nibbles) */
		if (fread(buf,1,4,infile)!=4) return 10;
		type_unk0 = buf[0];
		type_id=buf[1];
		root_key = buf[2];
		type_unk3 = buf[3];
		switch (type_id) {
		case 0:
			type=SRC_AFC_HQ_FROM_ARAM;
			break;
		case 1:
			type=SRC_AFC_LQ_FROM_ARAM;
			break;
		case 2:
			type=SRC_PCM8_FROM_ARAM;
			break;
		case 3:
			type=SRC_PCM16_FROM_ARAM;
			break;
		default:
			type=0;
			break;
		}

		/* contains srate */
		if (fread(buf,1,4,infile)!=4) return 11;
		srate=((buf[1]<<8) | buf[2])/2;
//		if (type==5) srate=32000;	/* hack - not sure whether this is true generally */

		/* offset */
		if (fread(buf,1,4,infile)!=4) return 12;
		afcoffset=read32(buf);

		/* size */
		if (fread(buf,1,4,infile)!=4) return 13;
		afcsize=read32(buf);
		
		if (fseek(infile,4,SEEK_CUR)<0) return 14;
		
		if (fread(buf,1,4,infile)!=4) return 15;
		loop_start_sample=read32(buf);

		if (fread(buf,1,4,infile)!=4) return 16;
		loop_end_sample=read32(buf);

		if (fread(buf,1,4,infile)!=4) return 17;
		num_samples=read32(buf);

		if (fread(buf,1,4,infile)!=4) return 18;
		unk0=read32(buf);

		if (fread(buf,1,4,infile)!=4) return 19;
		unk1=read32(buf);

		if (fread(buf,1,4,infile)!=4) return 20;
		unk2=read32(buf);

		if (verbose) {
			printf("%x\t%x\t%x\t%d\t%x\t%d\t%d\t%d\t%d\t%08x",i, afcoffset, afcsize, srate, type_id, root_key, loop_start_sample, loop_end_sample, num_samples, unk0);
			if (type == 0) {
				printf("\ttype_id=%x", type_id);
			}
			if (type_unk0 != 0xFF && type_unk0 != 0x70) {
				printf("\ttype_unk0=%x", type_unk0);
			}
			if (type_unk3 != 0) {
				printf("\ttype_unk3=%x", type_unk3);
			}
			if (unk1 != 0) {
				printf("\tunk1=%x", unk1);
			}
			if (unk2 != 0x01D8 && unk2 != 0x0018) {
				printf("\tunk2=%x", unk2);
			}
			printf("\n");
		}
		
		if (dump && type != 0) {
			snprintf(outname,sizeof(outname),"%s/%s_%08x.wav",output_dir,fname,i);
			FILE* outfile = fopen(outname,"wb");
			if (!outfile) return 21;
			
			int total_size = sizeof(wavhead)-8;
			
			total_size += sizeof(datahead);
			
			if (type == SRC_PCM16_FROM_ARAM || type == SRC_PCM8_FROM_ARAM) {
				total_size += afcsize;
			}
			else {
				total_size += afcsize/((type==SRC_AFC_LQ_FROM_ARAM) ? 5 : 9)*16*2;
			}
			
			int outframesize = (type==SRC_PCM8_FROM_ARAM) ? 1 : 2;
			
			if (writeWAVHead(outfile, total_size, srate, outframesize)) return 22;
			
			total_size += sizeof(smplhead);
			writeSMPL(outfile, srate, root_key, loop_start_sample, loop_end_sample);

			long oldpos = ftell(awfile);
			if (oldpos < 0) return 23;
			if (fseek(awfile,afcoffset,SEEK_SET)<0) return 24;

			if (type == SRC_PCM16_FROM_ARAM || type == SRC_PCM8_FROM_ARAM) {
				if (dumpPCM(awfile,afcsize,type,outfile)) return 25;
			}
			else {
				if (dumpAFC(awfile,afcsize,type,outfile)) return 26;
			}

			if (fseek(awfile,oldpos,SEEK_SET)<0) return 27;
			
			if (ftell(outfile) != total_size+8) {
				if (verbose) printf("Miscalculated WAV size %ld vs %d\n", ftell(outfile), total_size+8);
				return 28;
			}
			if (fclose(outfile)==EOF) return 29;
		}
	}

	if (dump) {
		if (fclose(awfile)==EOF) return 30;
	}

	if (fseek(infile,next_aw_offset,SEEK_SET)<0) return 31;

	return 0;
}

int doOscTable(FILE *infile) {
	unsigned char buf[4];
	//   80287aec load half (0000,0000,000e) at s pointer
	//   80287af4 add 6 to pointer
	//   80287af8 if half < 10, loop
	if (verbose) {
		printf("OscTable@0x%x", ftell(infile));
	}
	return 0;
}

int doOsc(FILE *infile, int ibnk_offset) {
	unsigned char buf[4];

	// 80287204 convert to Osc pointer (+IBNK)
	// 8028721c call findOscPtr
	//   802879d4 read word (000016e0) at BANK+4
	//   802879d8 convert to inst pointer
	//   802879f4 read word (000008e0) at INST+0x10
	//   802879f8 convert to osc pointer
	//   if 0, break
	//   80287a1c call BasicBank.getInst

	// 80287270 read byte (0) at IBNK+offset
	if (fread(buf,1,4,infile)!=4) return 1;
	unsigned char osc_1 = buf[3];

	// 80287278 read float (1.0) at IBNK+offset+4
	if (fread(buf,1,4,infile)!=4) return 1;
	float osc_f1 = readfloat(buf);

	// 80287284 read word (000006a0) at IBNK+offset+8
	if (fread(buf,1,4,infile)!=4) return 1;
	int osc_s_offset1 = read32(buf);

	// 80287318 read word (00000560) at IBNK+offset+0xC
	if (fread(buf,1,4,infile)!=4) return 1;
	int osc_s_offset2 = read32(buf);

	// 802873a8 load float (1.0) at IBNK+offset+0x10
	if (fread(buf,1,4,infile)!=4) return 1;
	float osc_f2 = readfloat(buf);

	// 802873b0 load float (0.0) at IBNK+offset+0x14
	if (fread(buf,1,4,infile)!=4) return 1;
	float osc_f3 = readfloat(buf);

	// 802873c4 call setOsc
	if (verbose) {
		printf("%x,%f,", osc_1, osc_f1);
	}
	
	int endOffset = ftell(infile);
	if (fseek(infile, osc_s_offset1+ibnk_offset, SEEK_SET)<0) return 1;
	if (doOscTable(infile)) return 1;
	if (fseek(infile, osc_s_offset2+ibnk_offset, SEEK_SET)<0) return 1;
	if (doOscTable(infile)) return 1;
	if (fseek(infile, endOffset, SEEK_SET)<0) return 1;

	if (verbose) {
		printf("%f,%f", osc_f2, osc_f3);
	}

	return 0;
}

int doVmap(FILE *infile) {
	unsigned char buf[4];

	// 8028762c read byte (7f) at 0
	// 80287634 read word (00000020) at 4
	// 80287640 read float (1.0) at 8
	// 80287648 read float (1.0) at 0xC
	if (fread(buf,1,4,infile)!=4) return 1;
	char vmap1 = buf[0];
	if (fread(buf,1,4,infile)!=4) return 1;
	int vmap2 = read32(buf);
	if (fread(buf,1,4,infile)!=4) return 1;
	float vmap3 = readfloat(buf);
	if (fread(buf,1,4,infile)!=4) return 1;
	float vmap4 = readfloat(buf);

	if (verbose) {
		printf("Vmap: %x,%x,%f,%f|", vmap1, vmap2, vmap3, vmap4);
	}
	
	return 0;
}

int doKeymap(FILE *infile, const int offset) {
	unsigned char buf[4];

	// 802875ec read byte (3b) at 0
	// 802875f8 read word (00000001) at 4
	// 802875fc call setVeloRegionCount
	// 80287658 read word (00000001) at 4
	// 80287614 call getVeloRegion
	// 80287624 read word (00000a00) at 8
	// that's a pointer to a vmap (814a9f30 in mem, A530 in file)

	if (fread(buf,1,4,infile)!=4) return 1;
	char keymap1 = buf[0];
	if (fread(buf,1,4,infile)!=4) return 1;
	int keymap2 = read32(buf);
	if (verbose) {
		printf("Keymap: %x,%x|", keymap1, keymap2);
	}
	if (fread(buf,1,4,infile)!=4) return 1;
	int vmap_offset = read32(buf);

	if (fseek(infile, vmap_offset+offset, SEEK_SET)<0) return 1;
	if (doVmap(infile)) return 1;
	
	// 80287658 read word (00000001) at 4
	// 8028766c read inst sub offset again
	// 802875d0 call getKeyRegion
	return 0;
}

int doInst(FILE * infile, const int offset) {
	unsigned char buf[4];

	if (fread(buf,1,4,infile)!=4) return 1;
	if (read32(buf) != 0) {
		fprintf(stderr, "Unexpected non-0 at 0x%lx\n", ftell(infile));
		return 1;
	}
	// 802871d0 read float at INST+8
	if (fread(buf,1,4,infile)!=4) return 1;
	float f1 = readfloat(buf);
	// 802871d8 read float at INST+0xC
	if (fread(buf,1,4,infile)!=4) return 1;
	float f2 = readfloat(buf);
	if (verbose) {
		printf("(%f,%f)|", f1, f2);
	}
	// 802871e8 call BasicInst.setOscCount
	for (int i = 0; i < 6; i++) {
		// 80287200 read word at INST+0x10
		if (fread(buf,1,4,infile)!=4) return 1;
		int osc_offset = read32(buf);
		if (osc_offset != 0) {
			int next_osc_offset = ftell(infile);
		
			if (verbose) {
				printf("Osc@0x%x:", osc_offset+offset);
			}
			if (fseek(infile, osc_offset+offset, SEEK_SET)<0) return 1;
			if (doOsc(infile, offset)) return 1;
			if (fseek(infile, next_osc_offset, SEEK_SET)<0) return 1;
			if (verbose) {
				printf("|");
			}
		}
	}
	if (fread(buf,1,4,infile)!=4) return 1;
	int inst_sub_offset_count = read32(buf);
	for (int i = 0; i < inst_sub_offset_count; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int keymap_offset = read32(buf);
		int next_sub_offset = ftell(infile);
	
		// points to a keymap, relative to IBNK start
		if (fseek(infile, keymap_offset+offset, SEEK_SET)<0) return 1;
		if (doKeymap(infile, offset)) return 1;
		if (fseek(infile, next_sub_offset, SEEK_SET)<0) return 1;
	}
	if (verbose) {
		printf("\n");
	}
	return 0;
}

int doNewInst(FILE *infile) {
	unsigned char buf[4];
	int i;

	if (fread(buf,1,4,infile)!=4) return 1;
	int n1 = read32(buf);
	int nCount;
	if (n1 == 1) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int n2 = read32(buf);
		if (verbose) {
			printf("(%d", n2);
		}
		if (fread(buf,1,4,infile)!=4) return 1;
		nCount = read32(buf);
	}
	else if (n1 == 2) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int n2 = read32(buf);
		if (verbose) {
			printf("(%d", n2);
		}
		if (fread(buf,1,4,infile)!=4) return 1;
		int n3 = read32(buf);
		if (verbose) {
			printf(",%d", n3);
		}
		if (fread(buf,1,4,infile)!=4) return 1;
		nCount = read32(buf);
	}
	else {
		fprintf(stderr, "0x%lX: Expected 1 or 2 got %x\n", ftell(infile)-4, n1);
		return 1;
	}
	for (i = 0; i < nCount; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int n5 = read32(buf);
		if (verbose) {
			printf(",%d", n5);
		}
	}
	if (verbose) {
		printf(")");
	}
	if (fread(buf,1,4,infile)!=4) return 1;
	int inst_sub_count = read32(buf);
	for (i = 0; i < inst_sub_count; i++) {
		// TODO
		if (fseek(infile,0x04,SEEK_CUR)<0) return 1;
		
		if (fread(buf,1,4,infile)!=4) return 1;
		int sz = read32(buf);
		if (verbose) printf("|%d:",sz);
		if (sz == 1) {
			// TODO
			if (fseek(infile,0x08,SEEK_CUR)<0) return 1;
		}
		else if (sz == 0) {
		}
		if (sz != 0) {
			if (fread(buf,1,4,infile)!=4) return 1;
			float sf1 = readfloat(buf);
			if (fread(buf,1,4,infile)!=4) return 1;
			float sf2 = readfloat(buf);
			if (verbose) {
				printf("%f,%f", sf1, sf2);
			}
		}
	}
	if (fread(buf,1,4,infile)!=4) return 1;
	float f1 = readfloat(buf);
	if (fread(buf,1,4,infile)!=4) return 1;
	float f2 = readfloat(buf);
	if (verbose) {
		printf("|(%f,%f)\n", f1, f2);
	}
	
	return 0;
}

int doPmap(FILE *infile) {
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"Pmap",4)) {
		fprintf(stderr,"Pmap expected at 0x%lx\n",ftell(infile)-4);
		return 1;
	}
	// TODO
	if (fseek(infile, 0x28, SEEK_CUR)<0) return 1;
	return 0;
}

int doPerc(FILE *infile, const int offset) {
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	int pmapCount = read32(buf);
	int i;
	for (i = 0; i < pmapCount; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int pmapOffset = read32(buf);
		if (pmapOffset == 0) continue;
		int nextOffset = ftell(infile);
		if (fseek(infile, pmapOffset+offset, SEEK_SET)<0) return 1;
		if (doPmap(infile)) return 1;
		if (fseek(infile, nextOffset, SEEK_SET)<0) return 1;
	}
	return 0;
}

static inline const int roundUp(const int numToRound, const int multiple) {  
	if (multiple == 0) {
		return numToRound;
	}

	const int remainder = numToRound % multiple;
	if (remainder == 0) {
		return numToRound;
	}
	return numToRound + multiple - remainder;
}

int doIBNK(FILE * infile, const int offset, int size) {
	unsigned char buf[4];
	int old_offset;
	
	old_offset = ftell(infile);
	if (old_offset<0) return 1;
	
	if (fseek(infile,offset,SEEK_SET)<0) return 1;
	
	/* IBNK tag */
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"IBNK",4)) {
		fprintf(stderr,"IBNK file expected at 0x%x\n",offset);
		return 1;
	}

	if (fread(buf,1,4,infile)!=4) return 1;
	if (size == 0) {
		size = read32(buf);
	}
	else if (read32(buf) != size) {
		fprintf(stderr, "Incorrect IBNK size\n");
		return 1;
	}
	
	if (fread(buf,1,4,infile)!=4) return 1;
	if (verbose) {
		printf("IBNK #%d\n", read32(buf));
	}
	
	int newstyle=0;
	//if (fseek(infile,24,SEEK_CUR)<0) return 1; /* skip stuff I don't use */
	for (int j = 0; j < 5; j++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		if (read32(buf) != 0) {
			//fprintf(stderr, "IBNK is not all 0 at 0x%lx!\n", ftell(infile));
			//return 1;
			newstyle=1;
		}
	}

	if (newstyle) {
		int readingChunks = 1;
		while (ftell(infile) < offset+size && readingChunks) {
			if (fread(buf,1,4,infile)!=4) return 1;
			int chunkId = read32(buf);
			if (fread(buf,1,4,infile)!=4) return 1;
			int chunkSize = read32(buf);
			switch (chunkId) {
			case 0:
				readingChunks = 0;
				break;
			/*case 0x494E5354: // INST
				{
					if (fread(buf,1,4,infile)!=4) return 1;
					int instCount = read32(buf);
					for (int i = 0; i < instCount; i++) {
						if (fread(buf,1,4,infile)!=4) return 1;
						if (memcmp(buf,"Inst",4) != 0) {
							fprintf(stderr, "Unknown block %s at 0x%lx\n", buf, ftell(infile)-4);
							return 1;
						}
						if (verbose) {
							printf("Inst at 0x%lx", ftell(infile)-4);
						}
						if (doNewInst(infile)) return 1;
					}
				}
				break;*/
			case 0x4F534354: // OSCT
				{
					if (fread(buf,1,4,infile)!=4) return 1;
					int oscCount = read32(buf);
					for (int i = 0; i < oscCount; i++) {
						if (fread(buf,1,4,infile)!=4) return 1;
						if (memcmp(buf,"Osci",4) != 0) {
							fprintf(stderr, "Unknown block %s at 0x%lx\n", buf, ftell(infile)-4);
							return 1;
						}
						if (verbose) {
							printf("Osci@0x%lx:", ftell(infile)-4);
						}
						if (doOsc(infile, offset)) return 1;
						if (verbose) {
							printf("\n");
						}
					}
				}
				break;
			case 0x4C495354: // LIST
				{
					if (fread(buf,1,4,infile)!=4) return 1;
					int offsCount = read32(buf);
					for (int i = 0; i < offsCount; i++) {
						if (fread(buf,1,4,infile)!=4) return 1;
						int listItemOffset = read32(buf);
						if (listItemOffset == 0) continue;
						int nextOffset = ftell(infile);
						if (fseek(infile, listItemOffset+offset, SEEK_SET)<0) return 1;
						if (fread(buf,1,4,infile)!=4) return 1;
						if (memcmp(buf,"Inst",4) == 0) {
							if (verbose) {
								printf("Inst at 0x%lx", ftell(infile)-4);
							}
							if (doNewInst(infile)) return 1;
						}
						else if (memcmp(buf,"Perc",4) == 0) {
							if (verbose) {
								printf("Perc at 0x%lx", ftell(infile)-4);
							}
							if (doPerc(infile, offset)) return 1;
						}
						else {
							fprintf(stderr, "Unknown chunk %c%c%c%c at 0x%lx\n", buf[0], buf[1], buf[2], buf[3], ftell(infile)-4);
						}
						if (fseek(infile, nextOffset, SEEK_SET)<0) return 1;
					}
				}
			default:
				if (fseek(infile,roundUp(chunkSize,4),SEEK_CUR)<0) return 1;
				break;
			}
		}
	}
	else {
		/* BANK tag */
		if (fread(buf,1,4,infile)!=4) return 1;
		if (memcmp(buf,"BANK",4)) {
			fprintf(stderr,"BANK file expected at 0x%x\n",offset+0x20);
			return 1;
		}
	
		for (int chunk_offset_pos = offset+0x24; chunk_offset_pos < offset+0x390; chunk_offset_pos += 4) {
			if (fseek(infile,chunk_offset_pos,SEEK_SET)<0) return 1;
			// 80287168 read word (000016e0) at IBNK+0x24 (BANK+4)
			if (fread(buf,1,4,infile)!=4) return 1;
			int chunk_offset = read32(buf);
			// 8028716c convert to inst pointer
			if (chunk_offset == 0) continue;
			if (chunk_offset > size) {
				fprintf(stderr, "Invalid BANK chunk pos %x\n", chunk_offset);
				return 1;
			}
			// 80287190 construct BasicInst
			if (fseek(infile,chunk_offset+offset,SEEK_SET)<0) return 1;
			if (fread(buf,1,4,infile)!=4) return 1;
			if (memcmp(buf,"INST",4) != 0) {
				fprintf(stderr, "Unknown block %s at 0x%x (from 0x%x)\n", buf, chunk_offset+offset, chunk_offset_pos);
				return 1;
			}
			if (verbose) {
				printf("INST at 0x%x ", chunk_offset+offset);
			}
			if (doInst(infile, offset)) return 1;
		}
		for (int chunk_offset_pos = offset+0x390; chunk_offset_pos < offset+0x400; chunk_offset_pos += 4) {
			if (fseek(infile,chunk_offset_pos,SEEK_SET)<0) return 1;
			if (fread(buf,1,4,infile)!=4) return 1;
			int chunk_offset = read32(buf);
			if (chunk_offset == 0) continue;
			if (chunk_offset > size) {
				fprintf(stderr, "Invalid BANK chunk pos %x\n", chunk_offset);
				return 1;
			}
			// 802876b4
			if (fseek(infile,chunk_offset+offset,SEEK_SET)<0) return 1;
			if (fread(buf,1,4,infile)!=4) return 1;
			if (memcmp(buf,"PER2",4) != 0) {
				fprintf(stderr, "Unknown block %s at 0x%x (from 0x%x)\n", buf, chunk_offset+offset, chunk_offset_pos);
				return 1;
			}
			// 80287758 read word (00000000) at PER+0x88
			// 8028775c convert pointer to Pmap
			if (verbose) {
				printf("PER2 at 0x%x\n", chunk_offset+offset);
			}
		}
	}
	
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;
	
	return 0;
}

int dostrm(FILE * infile, const int offset, const int size) {
	unsigned char buf[4];
	int old_offset;
	char afc_name[16];
	
	old_offset = ftell(infile);
	if (old_offset<0) return 1;
	
	if (fseek(infile,offset,SEEK_SET)<0) return 1;

	if (fseek(infile,16,SEEK_CUR)<0) return 1; // TODO
	
	while (ftell(infile) < offset+size) {
		if (fread(afc_name,1,16,infile) != 16) return 1;
		if (afc_name[15] != '\0') {
			fprintf(stderr, "Expected NULL terminator in AFC filename\n");
			return 1;
		}
	
		// Same as AFC header
		if (fread(buf,1,4,infile)!=4) return 1;
		int datalength = read32(buf);
	
		if (fread(buf,1,4,infile)!=4) return 1;
		int num_samples = read32(buf);
	
		if (fread(buf,1,2,infile)!=2) return 1;
		short sample_rate = read16(buf);
	
		if (fread(buf,1,2,infile)!=2) return 1;
		short unk1 = read16(buf);

		if (fread(buf,1,2,infile)!=2) return 1;
		short unk2 = read16(buf);

		if (fread(buf,1,2,infile)!=2) return 1;
		short unk3 = read16(buf);

		if (fread(buf,1,4,infile)!=4) return 1;
		int loop_flag = read32(buf);
	
		if (fread(buf,1,4,infile)!=4) return 1;
		int loop_start_sample = read32(buf);
	
		if (fread(buf,1,4,infile)!=4) return 1;
		int unk4 = read32(buf);

		if (fread(buf,1,4,infile)!=4) return 1;
		int unk5 = read32(buf);
		
		if (unk4 != 0 || unk5 != 0) {
			fprintf(stderr, "Unexpected not 0\n");
			return 1;
		}
		
		if (verbose) {
			printf("STRM %s\tsize=%x\tsamples=%x\trate=%d\tloop=%d\tstart=%d\t%x,%x,%x\n",
						 afc_name, datalength, num_samples, sample_rate, loop_flag, loop_start_sample, unk1, unk2, unk3);
		}
	}
	
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;
	
	return 0;
}

int doBARC(FILE * infile, const int offset, const int dump) {
	unsigned char buf[4];
	int old_offset;
	int seq_count;
	char arc_name[16] = {0};
	int i;
	FILE *arcFile;
		
	old_offset = ftell(infile);
	if (old_offset<0) return 1;
	
	if (fseek(infile,offset,SEEK_SET)<0) return 1;

	/* BARC tag */
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"BARC",4)) {
		fprintf(stderr,"BARC file expected at 0x%x\n",offset);
		return 1;
	}

	if (fseek(infile,8,SEEK_CUR)<0) return 1; /* skip stuff I don't use */
	
	if (fread(buf,1,4,infile)!=4) return 1;
	seq_count = read32(buf);
	
	if (fread(arc_name,1,16,infile) != 16) return 1;
	if (arc_name[15] != '\0') {
		fprintf(stderr, "Expected NULL terminator in ARC filename\n");
		return 1;
	}
	
	if (dump) {
		char inname[sizeof(arc_name)+5];
		snprintf(inname, sizeof(inname), "%s/%s", "Seqs", arc_name);
		arcFile = fopen(inname,"rb");
		if (!arcFile) return 1;
	}
	
	for (i=0;i<seq_count;i++) {
		char seq_name[14] = {0};
		int unk;
		int seq_size, seq_offset;
		if (fread(seq_name,1,14,infile) != 14) return 1;
		if (seq_name[13] != '\0') {
			fprintf(stderr, "Expected NULL terminator in sequence filename\n");
			return 1;
		}
		if (fseek(infile,6,SEEK_CUR)<0) return 1; /* skip stuff I don't use */
		
		if (fread(buf,1,4,infile)!=4) return 1;
		unk = read32(buf);
		
		if (fread(buf,1,4,infile)!=4) return 1;
		seq_offset = read32(buf);
		
		if (fread(buf,1,4,infile)!=4) return 1;
		seq_size = read32(buf);
		
		if (verbose) {
			printf("SEQ: %s\toffset\t%x\tsize\t%x\t?\t%x\n", seq_name, seq_offset, seq_size, unk);
		}
		if (dump) {
			char outname[128];
			FILE *outfile;
			
			// null out file extension
			char *extptr = strrchr(seq_name, '.');
			if (extptr != NULL && (extptr[1] == 'c' || extptr[1] == '\0')) extptr[0] = '\0';
			
			snprintf(outname,sizeof(outname), "%s/%s%d.com",output_dir,seq_name,i);
			outfile=fopen(outname, "wb");
			if (!outfile) return 1;
			if (fseek(arcFile,seq_offset,SEEK_SET)<0) return 1;
			for (int j = 0; j < seq_size; j += 4) {
				int sz = fread(buf,1,4,arcFile);
				if (sz < 1) return 1;
				if (fwrite(buf,1,sz,outfile) != sz) return 1;
			}
			if (fclose(outfile)==EOF) return 1;
		}
	}

	if (dump) {
		if (fclose(arcFile)==EOF) return 1;
	}
	
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;
	
	return 0;
}

int doWSYS(FILE * infile, const int offset, int size, int dump) {
	unsigned char buf[4];
	int WINFoffset, WBCToffset;
	int aw_count;
	int scne_count;
	int old_offset;
	int i;

	old_offset = ftell(infile);
	if (old_offset<0) return 1;

	if (fseek(infile,offset,SEEK_SET)<0) return 1;

	/* WSYS tag */
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"WSYS",4)) {
		fprintf(stderr,"WSYS file expected at 0x%x\n",offset);
		return 1;
	}
	
	if (verbose) printf("WSYS %X\n", offset);

	if (fread(buf,1,4,infile)!=4) return 1;
	int newSz = read32(buf);
	if (size != 0 && (size-newSz > 0x20 || newSz > size)) {
		fprintf(stderr, "WSYS file has incorrect size (0x%X vs 0x%X)\n", newSz, size);
		return 1;
	}
	
	if (fseek(infile,8,SEEK_CUR)<0) return 1; /* skip stuff I don't use */

	/* offset of WINF */
	if (fread(buf,1,4,infile)!=4) return 1;
	WINFoffset = read32(buf) + offset;

	if (fread(buf,1,4,infile)!=4) return 1;
	WBCToffset = read32(buf) + offset;
	
	if (fseek(infile,WINFoffset,SEEK_SET)<0) return 1;

	/* WINF tag */
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"WINF",4)) {
		fprintf(stderr,"expected WINF tag at 0x%x\n",WINFoffset);
		return 1;
	}

	/* number of .aw files to decode */
	if (fread(buf,1,4,infile)!=4) return 1;
	aw_count = read32(buf);

	for (i=0;i<aw_count;i++) {
		if (doaw(infile, offset, dump)) {
			fprintf(stderr, "error parsing .aw file\n");
			return 1;
		}
	}

	if (fseek(infile,WBCToffset,SEEK_SET)<0) return 1;
	/* WBCT tag */
	if (fread(buf,1,4,infile)!=4) return 1;
	if (memcmp(buf,"WBCT",4)) {
		fprintf(stderr,"expected WBCT tag at 0x%x\n",WBCToffset);
		return 1;
	}

	if (fseek(infile,4,SEEK_CUR)<0) return 1;
	if (fread(buf,1,4,infile)!=4) return 1;
	scne_count = read32(buf);
	for (i = 0; i < scne_count; i++) {
		int SCNEoffset, CSToffset, CEXoffset, CDFoffset;
		if (fread(buf,1,4,infile)!=4) return 1;
		SCNEoffset = read32(buf) + offset;
		int next_scne = ftell(infile);
		
		if (fseek(infile,SCNEoffset,SEEK_SET)<0) return 1;
		/* SCNE tag */
		if (fread(buf,1,4,infile)!=4) return 1;
		if (memcmp(buf,"SCNE",4)) {
			fprintf(stderr,"expected SCNE tag at 0x%x\n",SCNEoffset);
			return 1;
		}
	
		if (verbose) printf("SCNE %X\n", SCNEoffset);
		
		if (fseek(infile,8,SEEK_CUR)<0) return 1;
		if (fread(buf,1,4,infile)!=4) return 1;
		CDFoffset = read32(buf) + offset;
		if (fread(buf,1,4,infile)!=4) return 1;
		CEXoffset = read32(buf) + offset;
		if (fread(buf,1,4,infile)!=4) return 1;
		CSToffset = read32(buf) + offset;

		if (fseek(infile,CDFoffset,SEEK_SET)<0) return 1;
		/* C-DF tag */
		if (fread(buf,1,4,infile)!=4) return 1;
		if (memcmp(buf,"C-DF",4)) {
			fprintf(stderr,"expected C-DF tag at 0x%x\n",CDFoffset);
			return 1;
		}
		if (fread(buf,1,4,infile)!=4) return 1;
		int block_count = read32(buf);
		for (int j = 0; j < block_count; j++) {
			if (fread(buf,1,4,infile)!=4) return 1;
			int block_offset = read32(buf) + offset;
			int next_block_offset = ftell(infile);
			if (fseek(infile, block_offset, SEEK_SET)<0) return 1;
			if (fread(buf,1,4,infile)!=4) return 1;
			int scene_id = read16(buf);
			int block_id = read16(buf+2);
			if (verbose) {
				printf("C-DF %d scene %d block %04x at %04x\n", j, scene_id, block_id, block_offset);
			}
			if (fseek(infile, next_block_offset, SEEK_SET)<0) return 1;
		}

		if (fseek(infile,CEXoffset,SEEK_SET)<0) return 1;
		/* C-EX tag */
		if (fread(buf,1,4,infile)!=4) return 1;
		if (memcmp(buf,"C-EX",4)) {
			fprintf(stderr,"expected C-EX tag at 0x%x\n",CEXoffset);
			return 1;
		}
		for (int j = 0; j < 7; j++) {
			if (fread(buf,1,4,infile)!=4) return 1;
			if (read32(buf) != 0) {
				fprintf(stderr, "C-EX is not all 0 at 0x%lx!\n", ftell(infile));
				return 1;
			}
		}
		
		if (fseek(infile,CSToffset,SEEK_SET)<0) return 1;
		/* C-ST tag */
		if (fread(buf,1,4,infile)!=4) return 1;
		if (memcmp(buf,"C-ST",4)) {
			fprintf(stderr,"expected C-ST tag at 0x%x\n",CSToffset);
			return 1;
		}
		for (int j = 0; j < 7; j++) {
			if (fread(buf,1,4,infile)!=4) return 1;
			if (read32(buf) != 0) {
				fprintf(stderr, "C-ST is not all 0 at 0x%lx!\n", ftell(infile));
				return 1;
			}
		}
		
		if (fseek(infile,next_scne,SEEK_SET)<0) return 1;
	}
	
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;

	return 0;
}

int doBSTSection(FILE *infile, const int baseOffset, const int indent) {
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	if (buf[0] != 0 || buf[1] != 0) {
		fprintf(stderr, "Expected section at 0x%lX to start with 0\n", ftell(infile)-4-baseOffset);
		return 1;
	}
	int count = read32(buf);
	int i;
	if (verbose) {
		for (i = 0; i < indent; i++) putchar('\t');
		printf("0x%lX: %d\n", ftell(infile)-4-baseOffset, count);
	}
	if (indent == 2) {
		if (fread(buf,1,4,infile)!=4) return 1;
		if (read32(buf) != 0) {
			fprintf(stderr, "Expected 0 at 0x%lX\n", ftell(infile)-4-baseOffset);
			return 1;
		}
	}
	for (i = 0; i < count; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int subOffset = read16(buf+2);
		int next_offset = ftell(infile);
		if (buf[0] == 0x50 || buf[0] == 0x60 || buf[0] == 0x70) {
			continue;
		}
		if (buf[0] != 0 || buf[1] != 0) {
			fprintf(stderr, "Expected offset at 0x%lX to start with 0\n", ftell(infile)-4-baseOffset);
			return 1;
		}
		if (subOffset == 0) {
			fprintf(stderr, "Offset at 0x%lX is 0\n", ftell(infile)-4-baseOffset);
			return 1;
		}
		if (fseek(infile,baseOffset+subOffset,SEEK_SET)<0) return 1;
		if (doBSTSection(infile, baseOffset, indent+1)) return 1;
		if (fseek(infile,next_offset,SEEK_SET)<0) return 1;
	}
	return 0;
}

int doBSTSubCat(FILE *infile, const int baseOffset, const int indent) {
	unsigned char buf[4];
	char name_buf[0x20] = {0};
	if (fread(buf,1,4,infile)!=4) return 1;
	if (buf[0] != 0 || buf[1] != 0) {
		fprintf(stderr, "Expected items at 0x%lX to start with 0\n", ftell(infile)-4-baseOffset);
		return 1;
	}
	int count = read32(buf);
	int i;
	if (fread(buf,1,4,infile)!=4) return 1;
	int name_offset = read32(buf);
	if (name_offset != 0) {
		int offset_start = ftell(infile);
		if (fseek(infile,baseOffset+name_offset,SEEK_SET)<0) return 1;
		if (fread(name_buf, 1, 0x1F, infile) <= 0) return 1;
		if (fseek(infile,offset_start,SEEK_SET)<0) return 1;
	}
	if (verbose) {
		for (i = 0; i < indent; i++) putchar('\t');
		printf("0x%lX: %s %d", ftell(infile)-8-baseOffset, name_buf, count);
	}
	for (i = 0; i < count; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int name_offset = read32(buf);
		int next_offset = ftell(infile);
		if (name_offset == 0) {
			fprintf(stderr, "Offset at 0x%lX is 0\n", ftell(infile)-4-baseOffset);
			return 1;
		}
		if (name_offset != 0) {
			if (fseek(infile,baseOffset+name_offset,SEEK_SET)<0) return 1;
			if (fread(name_buf, 1, 0x1F, infile) <= 0) return 1;
			if (verbose) {
				printf(" %s", name_buf);
			}
			if (fseek(infile,next_offset,SEEK_SET)<0) return 1;
		}
	}
	if (verbose) {
		printf("\n");
	}
	return 0;
}

int doBSTCategory(FILE *infile, const int baseOffset, const int indent) {
	unsigned char buf[4];
	char name_buf[0x20] = {0};
	if (fread(buf,1,4,infile)!=4) return 1;
	if (buf[0] != 0 || buf[1] != 0) {
		fprintf(stderr, "Expected category at 0x%lX to start with 0\n", ftell(infile)-4-baseOffset);
		return 1;
	}
	int count = read32(buf);
	int i;
	if (fread(buf,1,4,infile)!=4) return 1;
	int name_offset = read32(buf);
	if (name_offset != 0) {
		int offset_start = ftell(infile);
		if (fseek(infile,baseOffset+name_offset,SEEK_SET)<0) return 1;
		if (fread(name_buf, 1, 0x1F, infile) <= 0) return 1;
		if (fseek(infile,offset_start,SEEK_SET)<0) return 1;
	}
	if (verbose) {
		for (i = 0; i < indent; i++) putchar('\t');
		printf("0x%lX: %s %d\n", ftell(infile)-8-baseOffset, name_buf, count);
	}
	for (i = 0; i < count; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int subOffset = read32(buf);
		int next_offset = ftell(infile);
		if (subOffset == 0) {
			fprintf(stderr, "Offset at 0x%lX is 0\n", ftell(infile)-4-baseOffset);
			return 1;
		}
		if (fseek(infile,baseOffset+subOffset,SEEK_SET)<0) return 1;
		if (doBSTSubCat(infile, baseOffset, indent+1)) return 1;
		if (fseek(infile,next_offset,SEEK_SET)<0) return 1;
	}
	return 0;
}

int doBSTStart(FILE *infile, const int baseOffset, const int indent) {
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	if (buf[0] != 0 || buf[1] != 0) {
		fprintf(stderr, "Expected start at 0x%lX to start with 0\n", ftell(infile)-4-baseOffset);
		return 1;
	}
	int count = read32(buf);
	int i;
	if (verbose) {
		for (i = 0; i < indent; i++) putchar('\t');
		printf("0x%lX: %d\n", ftell(infile)-4-baseOffset, count);
	}
	for (i = 0; i < count; i++) {
		if (fread(buf,1,4,infile)!=4) return 1;
		int subOffset = read32(buf);
		int next_offset = ftell(infile);
		if (subOffset == 0) {
			fprintf(stderr, "Offset at 0x%lX is 0\n", ftell(infile)-4-baseOffset);
			return 1;
		}
		if (fseek(infile,baseOffset+subOffset,SEEK_SET)<0) return 1;
		if (doBSTCategory(infile, baseOffset, indent+1)) return 1;
		if (fseek(infile,next_offset,SEEK_SET)<0) return 1;
	}
	return 0;
}

int doBST(FILE * infile, const int offset) {
	// start at 0xC
	// offset to offset list
	// list starts with 'count'
	// then sometimes an extra word
	// then 'count' number of offsets
	// sometimes in pairs with a half, sometimes with a word
	// offset to either offset or offset list (etc.)
	int old_offset = ftell(infile);
	if (old_offset<0) return 1;
	if (fseek(infile,offset+0xC,SEEK_SET)<0) return 1;
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	if (fseek(infile,offset+read32(buf),SEEK_SET)<0) return 1;
	if (doBSTSection(infile, offset, 0)) return 1;
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;
	return 0;
}

int doBSTN(FILE * infile, const int offset) {
	int old_offset = ftell(infile);
	if (old_offset<0) return 1;
	if (fseek(infile,offset+0xC,SEEK_SET)<0) return 1;
	unsigned char buf[4];
	if (fread(buf,1,4,infile)!=4) return 1;
	if (fseek(infile,offset+read32(buf),SEEK_SET)<0) return 1;
	if (doBSTStart(infile, offset, 0)) return 1;
	if (fseek(infile,old_offset,SEEK_SET)<0) return 1;
	return 0;
}

int doSC(FILE * infile, const int offset) {
	// starts with size
	return 0;
}

int main(int argc, char ** argv) {
	FILE * infile = NULL;
	unsigned char buf[4];
	int badstuff=0;
	int chunksdone=0;
	char infilename[256] = "";
	int i;
	int dump=0;
	
	printf("wwdumpsnd 0.4 by hcs\ndump audio from Wind Waker or Super Mario Sunshine\nneeds JaiInit.aaf and *.aw in current directory\n(if Sunshine, the file is 'msound.aaf', from 'nintendo.szs',\nbut you'll need to rename it :))\n\n");

	for (i=1;i<argc;i++) {
		if (!strcmp("-v",argv[i])) verbose=1;
		else if (!strcmp("-d",argv[i])) dump=1;
		else if (!strcmp("-o",argv[i])) {
			i++;
			strncpy(output_dir, argv[i], 256);
		}
		else if (infilename[0] == 0) {
			strncpy(infilename, argv[i], 256);
		}
		else {
			printf("usage: %s [-v][-d][-o <dir>] <filename>\n",argv[0]);
			return 1;
		}
	}

	if (infilename[0] == 0) {
		printf("usage: %s [-v][-d][-o <dir>] <filename>\n",argv[0]);
		return 1;
	}
	
	if (dump) {
		if (access("Banks", X_OK|R_OK) == 0) {
			aw_dir = "Banks";
		}
		else if (access("Waves", X_OK|R_OK) == 0) {
			aw_dir = "Waves";
		}
		else {
			fprintf(stderr, "Banks/Waves folder not found/not readable. Trying current directory\n");
			aw_dir = ".";
		}
	}
	
	infile = fopen(infilename,"rb");
	
	if (!infile) {
		fprintf(stderr,"failed to open %s\n",infilename);
		return 1;
	}

	if (!verbose) printf("working...\n");

	/* read header (chunk descriptions) */
	while (!feof(infile) && !badstuff && !chunksdone) {
		int chunkid,offset,size,id;
		fread(buf,4,1,infile);

		chunkid = read32(buf);

		switch (chunkid) {
			case 1:
				// TODO: Lots of the offsets point inside chunk 1,
				// so maybe it's just a data section (and those offsets should be
				// relative to chunk 1 start)
			case 4:
			case 5:
			case 6:
			case 7:
				if (verbose) {
					printf("%d:\t",chunkid);
				}

				fread(buf,4,1,infile);
				offset=read32(buf);
				if (verbose) {
					printf("offset\t%08x\t",offset);
				}

				fread(buf,4,1,infile);
				size=read32(buf);
				if (verbose) {
					printf("size\t%08x\t",size);
				}

				/* maybe continue if this != 0 ? */
				fread(buf,4,1,infile);

				if (verbose) {
					printf("%08x",read32(buf));

					printf("\n");
				}
				if (chunkid == 4) {
					if (doBARC(infile, offset, dump)) {
						badstuff=1;
					}
				}
				else if (chunkid == 5) {
					if (dostrm(infile, offset, size)) {
						badstuff=1;
					}
				}
				else {
					fprintf(stderr, "Can't handle chunk id %d\n", chunkid);
				}
				break;
			case 2:
			case 3:
				while (!feof(infile) && !badstuff) {
					fread(buf,4,1,infile);
					offset=read32(buf);
					if (offset!=0) {
						if (verbose) {
							printf("%d:\toffset\t%08x\t",chunkid,offset);
						}
					} else break;

					fread(buf,4,1,infile);
					size=read32(buf);
					if (verbose) {
						printf("size\t%08x\t",size);
					}

					fread(buf,4,1,infile);
					id=read32(buf);
					if (verbose) {
						printf("id\t%08x",id);

						printf("\n");
					}

					if (chunkid==3) {
						if (doWSYS(infile, offset, size, dump)) {
							badstuff=1;
						}
					}
					else if (chunkid==2) {
						if (doIBNK(infile, offset, size)) {
							badstuff=1;
						}
					}
				}

				break;
			case 0x41415F3C: // AA_< - SMG2 start tag
				break;
			case 0x62737420: // bst
			case 0x6273746E: // bstn
			case 0x62736320: // bsc
				if (verbose) {
					printf("%lc:\t",chunkid);
				}

				fread(buf,4,1,infile);
				offset=read32(buf);
				if (verbose) {
					printf("offset\t%08x\t",offset);
				}
				fread(buf,4,1,infile);
				size=read32(buf)-offset;
				if (verbose) {
					printf("size\t%08x\n",size);
				}
				if (chunkid == 0x62737420) {
					if (doBST(infile, offset)) {
						badstuff=1;
					}
				}
				else if (chunkid == 0x6273746E) {
					if (doBSTN(infile, offset)) {
						badstuff=1;
					}
				}
				else if (chunkid == 0x62736320) {
					if (doSC(infile, offset)) {
						badstuff=1;
					}
				}
				break;
			case 0x77732020: // ws
				if (verbose) {
					printf("%lc:\t",chunkid);
				}
				fread(buf,4,1,infile);
				id=read32(buf);
				if (verbose) {
					printf("id\t%08x\t",id);
				}
				fread(buf,4,1,infile);
				offset=read32(buf);
				if (verbose) {
					printf("offset\t%08x\t",offset);
				}
				fread(buf,4,1,infile);
				//size=read32(buf)-offset;
				if (verbose) {
					printf("%08x\n",read32(buf));
				}
				if (chunkid == 0x77732020) {
					if (doWSYS(infile, offset, 0, dump)) {
						badstuff=1;
					}
				}
				break;
			case 0x626E6B20: // bnk
				if (verbose) {
					printf("%lc:\t",chunkid);
				}

				fread(buf,4,1,infile);
				id=read32(buf);
				if (verbose) {
						printf("id\t%08x\t",id);
				}
				fread(buf,4,1,infile);
				offset=read32(buf);
				if (verbose) {
					printf("offset\t%08x\n",offset);
				}
				if (chunkid == 0x626E6B20) {
					if (doIBNK(infile, offset, 0)) {
						badstuff=1;
					}
				}
				break;
			case 0:
			case 0x3E5F4141: // >_AA - SMG2 end tag
				chunksdone=1;
				break;
			default:
				fprintf(stderr,"unknown id 0x%x\n",chunkid);
				badstuff=1;
				break;
		}
	}

	if (feof(infile)) {
		fprintf(stderr,"end of file encountered while trying to read chunk layout\n");
		fclose(infile); infile = NULL;
		return 1;
	}
	if (badstuff) {
		fprintf(stderr,"dump failed\n");
		fclose(infile); infile = NULL;
		return 1;
	}

	if (verbose)
		printf("end of chunks at 0x%lx\n",ftell(infile));

	fclose(infile); infile = NULL;
}
