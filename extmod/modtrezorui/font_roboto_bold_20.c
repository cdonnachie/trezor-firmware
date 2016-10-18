#include "font_roboto_bold_20.h"

// first two bytes are width and height of the glyph
// third, fourth and fifth bytes are advance, bearingX and bearingY of the horizontal metrics of the glyph
// rest is packed 4-bit glyph data

/*   */ static const uint8_t Font_Roboto_Bold_20_glyph_32[] = { 0, 0, 5, 0, 0 };
/* ! */ static const uint8_t Font_Roboto_Bold_20_glyph_33[] = { 4, 14, 5, 1, 14, 239, 240, 239, 240, 223, 240, 223, 224, 207, 224, 191, 208, 191, 208, 175, 192, 175, 192, 0, 0, 0, 0, 143, 160, 255, 241, 143, 160 };
/* " */ static const uint8_t Font_Roboto_Bold_20_glyph_34[] = { 6, 5, 6, 0, 15, 143, 101, 249, 143, 101, 249, 143, 69, 247, 143, 37, 245, 143, 21, 244 };
/* # */ static const uint8_t Font_Roboto_Bold_20_glyph_35[] = { 12, 14, 12, 0, 14, 0, 0, 111, 80, 207, 0, 0, 0, 159, 32, 237, 0, 0, 0, 207, 1, 250, 0, 0, 0, 253, 4, 248, 0, 9, 255, 255, 255, 255, 249, 6, 189, 253, 190, 251, 182, 0, 8, 244, 13, 224, 0, 0, 11, 241, 15, 176, 0, 95, 255, 255, 255, 255, 208, 59, 191, 235, 223, 203, 128, 0, 79, 128, 159, 48, 0, 0, 111, 80, 207, 0, 0, 0, 159, 48, 237, 0, 0, 0, 191, 1, 251, 0, 0 };
/* $ */ static const uint8_t Font_Roboto_Bold_20_glyph_36[] = { 11, 19, 11, 0, 17, 0, 0, 1, 0, 0, 0, 0, 0, 249, 0, 0, 0, 0, 15, 144, 0, 0, 1, 157, 255, 179, 0, 1, 239, 255, 255, 244, 0, 159, 250, 71, 255, 208, 12, 255, 16, 11, 255, 32, 191, 243, 0, 54, 97, 6, 255, 231, 16, 0, 0, 9, 255, 255, 145, 0, 0, 4, 207, 255, 227, 0, 0, 0, 42, 255, 224, 39, 115, 0, 11, 255, 52, 255, 160, 0, 159, 244, 14, 255, 132, 111, 255, 16, 95, 255, 255, 255, 112, 0, 58, 239, 251, 64, 0, 0, 2, 246, 0, 0, 0, 0, 47, 96, 0, 0 };
/* % */ static const uint8_t Font_Roboto_Bold_20_glyph_37[] = { 14, 14, 15, 1, 14, 7, 239, 177, 0, 0, 0, 0, 127, 219, 252, 0, 28, 64, 0, 207, 16, 207, 32, 159, 48, 0, 239, 0, 175, 67, 249, 0, 0, 207, 16, 207, 45, 225, 0, 0, 127, 219, 253, 127, 96, 0, 0, 8, 239, 180, 252, 0, 0, 0, 0, 0, 11, 243, 158, 233, 0, 0, 0, 95, 138, 252, 207, 160, 0, 0, 237, 31, 224, 14, 240, 0, 8, 244, 31, 192, 13, 241, 0, 47, 160, 15, 224, 14, 240, 0, 60, 16, 10, 252, 207, 160, 0, 0, 0, 1, 158, 233, 16 };
/* & */ static const uint8_t Font_Roboto_Bold_20_glyph_38[] = { 13, 14, 13, 0, 14, 0, 5, 207, 233, 16, 0, 0, 7, 255, 255, 252, 0, 0, 0, 255, 213, 159, 244, 0, 0, 31, 246, 0, 255, 80, 0, 0, 255, 160, 143, 241, 0, 0, 8, 255, 223, 245, 0, 0, 0, 31, 255, 227, 0, 0, 0, 29, 255, 254, 32, 109, 208, 13, 255, 143, 253, 25, 254, 4, 255, 144, 95, 252, 239, 160, 95, 249, 0, 95, 255, 244, 2, 255, 247, 71, 239, 254, 0, 8, 255, 255, 255, 255, 248, 0, 5, 191, 253, 165, 207, 246 };
/* ' */ static const uint8_t Font_Roboto_Bold_20_glyph_39[] = { 3, 5, 3, 0, 15, 159, 137, 247, 159, 105, 245, 159, 64 };
/* ( */ static const uint8_t Font_Roboto_Bold_20_glyph_40[] = { 6, 20, 7, 1, 16, 0, 1, 163, 0, 12, 246, 0, 175, 144, 4, 254, 0, 11, 247, 0, 47, 243, 0, 111, 224, 0, 159, 192, 0, 191, 176, 0, 207, 144, 0, 207, 144, 0, 191, 176, 0, 159, 192, 0, 111, 224, 0, 47, 243, 0, 11, 247, 0, 4, 254, 0, 0, 175, 144, 0, 12, 246, 0, 1, 163 };
/* ) */ static const uint8_t Font_Roboto_Bold_20_glyph_41[] = { 6, 20, 7, 0, 16, 74, 16, 0, 127, 209, 0, 10, 251, 0, 1, 239, 80, 0, 143, 192, 0, 63, 243, 0, 15, 247, 0, 12, 251, 0, 11, 253, 0, 10, 254, 0, 10, 254, 0, 11, 253, 0, 12, 251, 0, 15, 247, 0, 63, 243, 0, 143, 192, 0, 239, 80, 9, 251, 0, 111, 209, 0, 74, 16, 0 };
/* * */ static const uint8_t Font_Roboto_Bold_20_glyph_42[] = { 9, 9, 9, 0, 14, 0, 4, 248, 0, 0, 0, 63, 128, 0, 75, 83, 247, 57, 119, 255, 255, 255, 250, 0, 78, 255, 81, 0, 8, 251, 249, 0, 5, 252, 11, 246, 0, 61, 32, 46, 80, 0, 0, 0, 0, 0 };
/* + */ static const uint8_t Font_Roboto_Bold_20_glyph_43[] = { 11, 11, 11, 0, 12, 0, 0, 205, 160, 0, 0, 0, 14, 252, 0, 0, 0, 0, 239, 192, 0, 0, 0, 14, 252, 0, 0, 127, 255, 255, 255, 255, 71, 255, 255, 255, 255, 244, 56, 136, 255, 232, 136, 32, 0, 14, 252, 0, 0, 0, 0, 239, 192, 0, 0, 0, 14, 252, 0, 0, 0, 0, 120, 96, 0, 0 };
/* , */ static const uint8_t Font_Roboto_Bold_20_glyph_44[] = { 4, 7, 5, 0, 3, 3, 101, 9, 252, 9, 252, 10, 251, 13, 247, 79, 225, 60, 80 };
/* - */ static const uint8_t Font_Roboto_Bold_20_glyph_45[] = { 6, 3, 8, 1, 7, 239, 255, 249, 239, 255, 249, 68, 68, 66 };
/* . */ static const uint8_t Font_Roboto_Bold_20_glyph_46[] = { 4, 4, 6, 1, 4, 0, 0, 78, 210, 175, 247, 78, 210 };
/* / */ static const uint8_t Font_Roboto_Bold_20_glyph_47[] = { 9, 15, 7, -1, 14, 0, 0, 1, 255, 0, 0, 0, 111, 160, 0, 0, 12, 245, 0, 0, 1, 255, 0, 0, 0, 127, 160, 0, 0, 13, 244, 0, 0, 2, 254, 0, 0, 0, 143, 144, 0, 0, 13, 243, 0, 0, 3, 254, 0, 0, 0, 143, 128, 0, 0, 14, 243, 0, 0, 4, 253, 0, 0, 0, 159, 112, 0, 0, 14, 242, 0, 0, 0 };
/* 0 */ static const uint8_t Font_Roboto_Bold_20_glyph_48[] = { 11, 14, 11, 0, 14, 0, 42, 239, 233, 16, 0, 46, 255, 255, 254, 16, 11, 255, 149, 175, 250, 1, 255, 208, 0, 223, 240, 63, 249, 0, 9, 255, 52, 255, 128, 0, 143, 244, 95, 248, 0, 8, 255, 69, 255, 128, 0, 143, 244, 79, 248, 0, 8, 255, 67, 255, 144, 0, 159, 242, 15, 253, 0, 13, 255, 0, 175, 250, 89, 255, 160, 2, 239, 255, 255, 225, 0, 1, 158, 254, 145, 0 };
/* 1 */ static const uint8_t Font_Roboto_Bold_20_glyph_49[] = { 7, 14, 11, 1, 14, 0, 0, 90, 192, 74, 255, 253, 111, 255, 255, 214, 251, 111, 253, 16, 0, 255, 208, 0, 15, 253, 0, 0, 255, 208, 0, 15, 253, 0, 0, 255, 208, 0, 15, 253, 0, 0, 255, 208, 0, 15, 253, 0, 0, 255, 208, 0, 15, 253 };
/* 2 */ static const uint8_t Font_Roboto_Bold_20_glyph_50[] = { 11, 14, 11, 0, 14, 0, 58, 239, 234, 48, 0, 95, 255, 255, 255, 48, 31, 255, 117, 175, 252, 6, 255, 128, 0, 239, 240, 72, 130, 0, 13, 255, 0, 0, 0, 3, 255, 160, 0, 0, 1, 223, 242, 0, 0, 0, 207, 246, 0, 0, 0, 191, 248, 0, 0, 0, 191, 248, 0, 0, 0, 191, 249, 0, 0, 0, 191, 252, 68, 68, 66, 79, 255, 255, 255, 255, 116, 255, 255, 255, 255, 247 };
/* 3 */ static const uint8_t Font_Roboto_Bold_20_glyph_51[] = { 11, 14, 11, 0, 14, 0, 75, 239, 233, 32, 0, 143, 255, 255, 255, 48, 47, 254, 117, 175, 252, 4, 187, 80, 0, 239, 240, 0, 0, 0, 13, 255, 0, 0, 0, 7, 255, 144, 0, 6, 255, 255, 160, 0, 0, 111, 255, 250, 16, 0, 1, 52, 143, 252, 0, 0, 0, 0, 175, 242, 142, 229, 0, 10, 255, 53, 255, 230, 89, 255, 224, 10, 255, 255, 255, 245, 0, 6, 207, 254, 162, 0 };
/* 4 */ static const uint8_t Font_Roboto_Bold_20_glyph_52[] = { 11, 14, 11, 0, 14, 0, 0, 0, 223, 245, 0, 0, 0, 127, 255, 80, 0, 0, 47, 255, 245, 0, 0, 11, 255, 255, 80, 0, 5, 255, 159, 245, 0, 1, 239, 120, 255, 80, 0, 159, 208, 143, 245, 0, 63, 244, 8, 255, 80, 13, 250, 0, 143, 245, 6, 255, 255, 255, 255, 254, 111, 255, 255, 255, 255, 225, 68, 68, 74, 255, 132, 0, 0, 0, 143, 245, 0, 0, 0, 8, 255, 80 };
/* 5 */ static const uint8_t Font_Roboto_Bold_20_glyph_53[] = { 11, 14, 11, 0, 14, 1, 255, 255, 255, 255, 0, 63, 255, 255, 255, 240, 5, 255, 133, 85, 85, 0, 111, 242, 0, 0, 0, 8, 255, 0, 0, 0, 0, 175, 250, 239, 197, 0, 12, 255, 255, 255, 247, 0, 73, 164, 38, 255, 241, 0, 0, 0, 9, 255, 64, 0, 0, 0, 127, 246, 31, 251, 0, 10, 255, 64, 223, 249, 88, 255, 224, 3, 255, 255, 255, 245, 0, 1, 158, 254, 163, 0 };
/* 6 */ static const uint8_t Font_Roboto_Bold_20_glyph_54[] = { 11, 14, 11, 0, 14, 0, 0, 57, 223, 96, 0, 0, 159, 255, 246, 0, 0, 175, 255, 150, 32, 0, 79, 253, 32, 0, 0, 11, 255, 48, 0, 0, 0, 255, 215, 223, 215, 0, 47, 255, 255, 255, 249, 3, 255, 248, 71, 255, 242, 63, 249, 0, 8, 255, 98, 255, 144, 0, 95, 248, 15, 253, 0, 8, 255, 96, 143, 250, 87, 255, 241, 0, 207, 255, 255, 246, 0, 0, 125, 254, 179, 0 };
/* 7 */ static const uint8_t Font_Roboto_Bold_20_glyph_55[] = { 11, 14, 11, 0, 14, 111, 255, 255, 255, 255, 166, 255, 255, 255, 255, 249, 20, 68, 68, 74, 255, 48, 0, 0, 0, 239, 192, 0, 0, 0, 111, 245, 0, 0, 0, 13, 254, 0, 0, 0, 5, 255, 112, 0, 0, 0, 207, 241, 0, 0, 0, 79, 249, 0, 0, 0, 11, 255, 32, 0, 0, 3, 255, 176, 0, 0, 0, 175, 243, 0, 0, 0, 47, 252, 0, 0, 0, 9, 255, 80, 0, 0 };
/* 8 */ static const uint8_t Font_Roboto_Bold_20_glyph_56[] = { 11, 14, 11, 0, 14, 0, 42, 239, 234, 32, 0, 63, 255, 255, 255, 48, 11, 255, 165, 175, 251, 0, 255, 224, 0, 239, 240, 14, 254, 0, 14, 254, 0, 175, 246, 6, 255, 144, 1, 207, 255, 255, 192, 0, 10, 255, 255, 250, 0, 11, 255, 133, 143, 251, 3, 255, 160, 0, 175, 242, 79, 250, 0, 10, 255, 65, 255, 248, 88, 255, 241, 7, 255, 255, 255, 247, 0, 4, 190, 254, 179, 0 };
/* 9 */ static const uint8_t Font_Roboto_Bold_20_glyph_57[] = { 11, 14, 11, 0, 14, 0, 41, 239, 215, 0, 0, 46, 255, 255, 252, 0, 13, 255, 149, 191, 247, 3, 255, 176, 0, 239, 224, 95, 247, 0, 10, 255, 20, 255, 144, 0, 175, 243, 31, 255, 64, 78, 255, 48, 159, 255, 255, 255, 242, 0, 143, 255, 173, 255, 0, 0, 2, 17, 255, 192, 0, 0, 0, 191, 245, 0, 1, 105, 239, 251, 0, 0, 79, 255, 251, 0, 0, 4, 253, 164, 0, 0 };
/* : */ static const uint8_t Font_Roboto_Bold_20_glyph_58[] = { 4, 11, 6, 1, 11, 78, 210, 175, 247, 78, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 210, 175, 247, 78, 210 };
/* ; */ static const uint8_t Font_Roboto_Bold_20_glyph_59[] = { 5, 15, 5, 0, 11, 4, 237, 32, 175, 247, 4, 238, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 101, 0, 159, 192, 9, 252, 0, 175, 176, 13, 247, 4, 254, 16, 60, 80, 0 };
/* < */ static const uint8_t Font_Roboto_Bold_20_glyph_60[] = { 9, 9, 10, 0, 11, 0, 0, 0, 6, 192, 0, 3, 159, 255, 0, 108, 255, 255, 181, 255, 255, 199, 16, 127, 253, 48, 0, 5, 255, 255, 198, 16, 0, 108, 255, 255, 176, 0, 3, 159, 255, 0, 0, 0, 6, 192 };
/* = */ static const uint8_t Font_Roboto_Bold_20_glyph_61[] = { 10, 7, 11, 1, 9, 175, 255, 255, 255, 241, 175, 255, 255, 255, 241, 53, 85, 85, 85, 80, 0, 0, 0, 0, 0, 175, 255, 255, 255, 241, 175, 255, 255, 255, 241, 53, 85, 85, 85, 80 };
/* > */ static const uint8_t Font_Roboto_Bold_20_glyph_62[] = { 9, 9, 10, 1, 11, 183, 16, 0, 0, 13, 255, 164, 0, 0, 159, 255, 253, 113, 0, 21, 191, 255, 247, 0, 0, 44, 255, 160, 22, 191, 255, 247, 159, 255, 253, 113, 13, 255, 164, 0, 0, 183, 16, 0, 0, 0 };
/* ? */ static const uint8_t Font_Roboto_Bold_20_glyph_63[] = { 10, 14, 10, 0, 14, 0, 125, 254, 197, 0, 11, 255, 255, 255, 128, 79, 254, 103, 255, 240, 127, 245, 0, 175, 243, 0, 0, 0, 191, 242, 0, 0, 4, 255, 192, 0, 0, 79, 254, 32, 0, 1, 255, 226, 0, 0, 6, 255, 64, 0, 0, 8, 255, 0, 0, 0, 0, 0, 0, 0, 0, 6, 235, 0, 0, 0, 13, 255, 48, 0, 0, 6, 252, 0, 0 };
/* @ */ static const uint8_t Font_Roboto_Bold_20_glyph_64[] = { 18, 18, 18, 0, 14, 0, 0, 1, 124, 239, 236, 113, 0, 0, 0, 0, 95, 254, 185, 174, 255, 64, 0, 0, 7, 254, 80, 0, 0, 77, 245, 0, 0, 63, 210, 0, 0, 0, 1, 238, 16, 0, 223, 48, 3, 207, 233, 16, 95, 112, 4, 250, 0, 79, 253, 223, 160, 14, 192, 10, 244, 0, 239, 80, 111, 144, 11, 240, 13, 240, 5, 252, 0, 143, 112, 10, 241, 15, 224, 10, 247, 0, 159, 96, 10, 241, 31, 208, 13, 245, 0, 175, 64, 11, 240, 15, 208, 13, 245, 0, 207, 48, 14, 208, 15, 240, 11, 249, 4, 255, 48, 111, 112, 12, 243, 5, 255, 223, 239, 217, 253, 0, 7, 249, 0, 143, 232, 26, 255, 161, 0, 1, 239, 64, 0, 0, 0, 0, 0, 0, 0, 95, 248, 16, 0, 2, 0, 0, 0, 0, 4, 255, 253, 188, 239, 64, 0, 0, 0, 0, 23, 206, 254, 200, 16, 0, 0 };
/* A */ static const uint8_t Font_Roboto_Bold_20_glyph_65[] = { 14, 14, 13, 0, 14, 0, 0, 13, 255, 64, 0, 0, 0, 0, 63, 255, 160, 0, 0, 0, 0, 159, 255, 241, 0, 0, 0, 0, 239, 239, 246, 0, 0, 0, 5, 255, 111, 252, 0, 0, 0, 11, 255, 26, 255, 32, 0, 0, 31, 252, 5, 255, 128, 0, 0, 127, 246, 0, 255, 224, 0, 0, 223, 241, 0, 175, 244, 0, 3, 255, 255, 255, 255, 251, 0, 9, 255, 255, 255, 255, 255, 16, 15, 255, 102, 102, 107, 255, 112, 95, 251, 0, 0, 4, 255, 208, 207, 245, 0, 0, 0, 239, 243 };
/* B */ static const uint8_t Font_Roboto_Bold_20_glyph_66[] = { 11, 14, 13, 1, 14, 175, 255, 255, 236, 96, 10, 255, 255, 255, 255, 176, 175, 249, 102, 143, 255, 90, 255, 80, 0, 127, 249, 175, 245, 0, 5, 255, 138, 255, 80, 3, 223, 243, 175, 255, 255, 255, 245, 10, 255, 255, 255, 255, 160, 175, 246, 17, 41, 255, 154, 255, 80, 0, 15, 254, 175, 245, 0, 2, 255, 234, 255, 149, 87, 223, 250, 175, 255, 255, 255, 254, 42, 255, 255, 255, 217, 16 };
/* C */ static const uint8_t Font_Roboto_Bold_20_glyph_67[] = { 13, 14, 13, 0, 14, 0, 2, 141, 255, 198, 0, 0, 4, 255, 255, 255, 252, 0, 1, 255, 251, 120, 223, 250, 0, 159, 248, 0, 0, 239, 241, 14, 255, 16, 0, 9, 255, 80, 255, 208, 0, 0, 0, 0, 47, 253, 0, 0, 0, 0, 2, 255, 208, 0, 0, 0, 0, 31, 253, 0, 0, 0, 0, 0, 239, 240, 0, 0, 143, 245, 9, 255, 112, 0, 14, 255, 32, 47, 255, 167, 125, 255, 176, 0, 95, 255, 255, 255, 193, 0, 0, 41, 239, 252, 112, 0 };
/* D */ static const uint8_t Font_Roboto_Bold_20_glyph_68[] = { 12, 14, 13, 1, 14, 191, 255, 254, 181, 0, 0, 191, 255, 255, 255, 193, 0, 191, 248, 103, 223, 252, 0, 191, 243, 0, 11, 255, 96, 191, 243, 0, 2, 255, 192, 191, 243, 0, 0, 239, 240, 191, 243, 0, 0, 223, 241, 191, 243, 0, 0, 223, 241, 191, 243, 0, 0, 255, 240, 191, 243, 0, 3, 255, 192, 191, 243, 0, 12, 255, 96, 191, 247, 87, 223, 252, 0, 191, 255, 255, 255, 193, 0, 191, 255, 254, 181, 0, 0 };
/* E */ static const uint8_t Font_Roboto_Bold_20_glyph_69[] = { 10, 14, 11, 1, 14, 191, 255, 255, 255, 252, 191, 255, 255, 255, 252, 191, 248, 102, 102, 100, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 255, 255, 255, 208, 191, 255, 255, 255, 208, 191, 247, 68, 68, 48, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 247, 85, 85, 84, 191, 255, 255, 255, 252, 191, 255, 255, 255, 252 };
/* F */ static const uint8_t Font_Roboto_Bold_20_glyph_70[] = { 10, 14, 11, 1, 14, 191, 255, 255, 255, 248, 191, 255, 255, 255, 248, 191, 248, 102, 102, 99, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 255, 255, 255, 208, 191, 255, 255, 255, 208, 191, 247, 85, 85, 64, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0 };
/* G */ static const uint8_t Font_Roboto_Bold_20_glyph_71[] = { 12, 14, 14, 1, 14, 0, 7, 206, 253, 146, 0, 2, 223, 255, 255, 255, 64, 12, 255, 215, 106, 255, 225, 79, 253, 0, 0, 159, 246, 175, 245, 0, 0, 60, 199, 207, 242, 0, 0, 0, 0, 223, 241, 0, 0, 0, 0, 239, 241, 0, 239, 255, 251, 207, 242, 0, 239, 255, 251, 175, 246, 0, 34, 95, 251, 79, 253, 0, 0, 63, 251, 12, 255, 215, 103, 207, 251, 1, 207, 255, 255, 255, 245, 0, 6, 206, 254, 199, 16 };
/* H */ static const uint8_t Font_Roboto_Bold_20_glyph_72[] = { 12, 14, 14, 1, 14, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 255, 255, 255, 255, 253, 191, 255, 255, 255, 255, 253, 191, 247, 85, 85, 111, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253, 191, 243, 0, 0, 31, 253 };
/* I */ static const uint8_t Font_Roboto_Bold_20_glyph_73[] = { 4, 14, 6, 1, 14, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246, 143, 246 };
/* J */ static const uint8_t Font_Roboto_Bold_20_glyph_74[] = { 10, 14, 11, 0, 14, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 0, 0, 0, 31, 253, 70, 97, 0, 31, 253, 159, 246, 0, 79, 251, 95, 254, 119, 239, 246, 11, 255, 255, 255, 176, 0, 124, 255, 199, 0 };
/* K */ static const uint8_t Font_Roboto_Bold_20_glyph_75[] = { 12, 14, 13, 1, 14, 159, 245, 0, 2, 255, 247, 159, 245, 0, 29, 255, 160, 159, 245, 0, 191, 252, 0, 159, 245, 8, 255, 225, 0, 159, 245, 79, 255, 48, 0, 159, 247, 239, 246, 0, 0, 159, 255, 255, 241, 0, 0, 159, 255, 255, 250, 0, 0, 159, 255, 207, 255, 80, 0, 159, 252, 6, 255, 225, 0, 159, 245, 0, 207, 250, 0, 159, 245, 0, 47, 255, 80, 159, 245, 0, 7, 255, 225, 159, 245, 0, 0, 207, 250 };
/* L */ static const uint8_t Font_Roboto_Bold_20_glyph_76[] = { 10, 14, 11, 1, 14, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 243, 0, 0, 0, 191, 247, 85, 85, 82, 191, 255, 255, 255, 246, 191, 255, 255, 255, 246 };
/* M */ static const uint8_t Font_Roboto_Bold_20_glyph_77[] = { 16, 14, 18, 1, 14, 191, 255, 64, 0, 0, 12, 255, 243, 191, 255, 160, 0, 0, 47, 255, 243, 191, 255, 240, 0, 0, 143, 255, 243, 191, 255, 245, 0, 0, 223, 255, 243, 191, 252, 251, 0, 3, 255, 191, 243, 191, 246, 255, 16, 9, 253, 143, 243, 191, 241, 255, 96, 14, 248, 143, 243, 191, 241, 175, 192, 79, 242, 159, 243, 191, 242, 79, 242, 175, 192, 175, 243, 191, 242, 14, 249, 255, 96, 175, 243, 191, 243, 8, 255, 255, 16, 191, 243, 191, 243, 3, 255, 250, 0, 191, 243, 191, 243, 0, 223, 244, 0, 191, 243, 191, 243, 0, 127, 224, 0, 191, 243 };
/* N */ static const uint8_t Font_Roboto_Bold_20_glyph_78[] = { 12, 14, 14, 1, 14, 223, 246, 0, 0, 63, 251, 223, 255, 16, 0, 63, 251, 223, 255, 160, 0, 63, 251, 223, 255, 244, 0, 63, 251, 223, 255, 253, 0, 63, 251, 223, 248, 255, 128, 63, 251, 223, 241, 223, 242, 63, 251, 223, 241, 63, 251, 63, 251, 223, 241, 9, 255, 143, 251, 223, 241, 1, 239, 255, 251, 223, 241, 0, 95, 255, 251, 223, 241, 0, 11, 255, 251, 223, 241, 0, 2, 255, 251, 223, 241, 0, 0, 127, 251 };
/* O */ static const uint8_t Font_Roboto_Bold_20_glyph_79[] = { 14, 14, 14, 0, 14, 0, 0, 124, 254, 199, 0, 0, 0, 45, 255, 255, 255, 210, 0, 0, 223, 253, 119, 223, 252, 0, 6, 255, 192, 0, 12, 255, 96, 12, 255, 64, 0, 3, 255, 176, 15, 255, 0, 0, 0, 255, 224, 15, 255, 0, 0, 0, 239, 240, 15, 255, 0, 0, 0, 239, 240, 15, 255, 0, 0, 0, 255, 224, 12, 255, 64, 0, 4, 255, 192, 6, 255, 192, 0, 12, 255, 96, 0, 223, 253, 119, 207, 253, 0, 0, 45, 255, 255, 255, 210, 0, 0, 0, 124, 255, 199, 0, 0 };
/* P */ static const uint8_t Font_Roboto_Bold_20_glyph_80[] = { 12, 14, 13, 1, 14, 191, 255, 255, 236, 112, 0, 191, 255, 255, 255, 252, 0, 191, 248, 102, 126, 255, 144, 191, 244, 0, 2, 255, 240, 191, 244, 0, 0, 207, 242, 191, 244, 0, 0, 239, 242, 191, 244, 0, 24, 255, 224, 191, 255, 255, 255, 255, 80, 191, 255, 255, 255, 229, 0, 191, 248, 101, 83, 0, 0, 191, 244, 0, 0, 0, 0, 191, 244, 0, 0, 0, 0, 191, 244, 0, 0, 0, 0, 191, 244, 0, 0, 0, 0 };
/* Q */ static const uint8_t Font_Roboto_Bold_20_glyph_81[] = { 14, 17, 14, 0, 14, 0, 0, 124, 254, 198, 0, 0, 0, 45, 255, 255, 255, 210, 0, 0, 223, 252, 119, 223, 252, 0, 6, 255, 176, 0, 12, 255, 80, 12, 255, 48, 0, 4, 255, 176, 15, 255, 0, 0, 0, 255, 224, 15, 254, 0, 0, 0, 255, 240, 15, 254, 0, 0, 0, 255, 240, 15, 255, 0, 0, 1, 255, 224, 12, 255, 64, 0, 4, 255, 176, 6, 255, 192, 0, 12, 255, 96, 0, 223, 252, 119, 207, 253, 0, 0, 45, 255, 255, 255, 225, 0, 0, 0, 124, 255, 255, 246, 0, 0, 0, 0, 0, 78, 255, 144, 0, 0, 0, 0, 2, 222, 32, 0, 0, 0, 0, 0, 1, 0 };
/* R */ static const uint8_t Font_Roboto_Bold_20_glyph_82[] = { 12, 14, 13, 1, 14, 159, 255, 255, 252, 112, 0, 159, 255, 255, 255, 252, 0, 159, 249, 102, 143, 255, 128, 159, 245, 0, 4, 255, 208, 159, 245, 0, 0, 255, 224, 159, 245, 0, 2, 255, 208, 159, 245, 0, 44, 255, 128, 159, 255, 255, 255, 252, 0, 159, 255, 255, 255, 176, 0, 159, 249, 103, 255, 224, 0, 159, 245, 0, 191, 247, 0, 159, 245, 0, 47, 255, 16, 159, 245, 0, 8, 255, 160, 159, 245, 0, 0, 239, 243 };
/* S */ static const uint8_t Font_Roboto_Bold_20_glyph_83[] = { 12, 14, 12, 0, 14, 0, 23, 207, 253, 146, 0, 2, 239, 255, 255, 255, 64, 11, 255, 198, 106, 255, 224, 15, 255, 0, 0, 191, 245, 15, 255, 64, 0, 19, 49, 8, 255, 251, 81, 0, 0, 0, 159, 255, 255, 162, 0, 0, 3, 175, 255, 255, 64, 0, 0, 0, 92, 255, 241, 55, 115, 0, 0, 191, 245, 95, 251, 0, 0, 159, 246, 14, 255, 182, 88, 255, 242, 3, 239, 255, 255, 255, 128, 0, 7, 206, 254, 180, 0 };
/* T */ static const uint8_t Font_Roboto_Bold_20_glyph_84[] = { 12, 14, 12, 0, 14, 159, 255, 255, 255, 255, 255, 159, 255, 255, 255, 255, 255, 54, 102, 159, 252, 102, 101, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 95, 250, 0, 0 };
/* U */ static const uint8_t Font_Roboto_Bold_20_glyph_85[] = { 11, 14, 13, 1, 14, 255, 240, 0, 0, 255, 255, 255, 0, 0, 15, 255, 255, 240, 0, 0, 255, 255, 255, 0, 0, 15, 255, 255, 240, 0, 0, 255, 255, 255, 0, 0, 15, 255, 255, 240, 0, 0, 255, 255, 255, 0, 0, 15, 255, 255, 240, 0, 0, 255, 254, 255, 0, 0, 15, 254, 207, 245, 0, 5, 255, 198, 255, 248, 104, 255, 246, 10, 255, 255, 255, 249, 0, 5, 190, 254, 181, 0 };
/* V */ static const uint8_t Font_Roboto_Bold_20_glyph_86[] = { 13, 14, 13, 0, 14, 207, 246, 0, 0, 7, 255, 199, 255, 176, 0, 0, 207, 246, 31, 255, 0, 0, 31, 255, 16, 207, 245, 0, 5, 255, 176, 6, 255, 160, 0, 175, 246, 0, 31, 254, 0, 15, 255, 0, 0, 191, 244, 4, 255, 160, 0, 5, 255, 128, 159, 245, 0, 0, 15, 253, 14, 254, 0, 0, 0, 175, 245, 255, 144, 0, 0, 4, 255, 239, 244, 0, 0, 0, 14, 255, 254, 0, 0, 0, 0, 159, 255, 128, 0, 0, 0, 3, 255, 243, 0, 0 };
/* W */ static const uint8_t Font_Roboto_Bold_20_glyph_87[] = { 17, 14, 17, 0, 14, 207, 241, 0, 13, 254, 0, 1, 255, 201, 255, 64, 1, 255, 241, 0, 79, 249, 95, 247, 0, 79, 255, 80, 7, 255, 81, 255, 176, 8, 255, 249, 0, 175, 242, 14, 254, 0, 207, 255, 208, 13, 254, 0, 175, 241, 15, 249, 255, 0, 255, 160, 7, 255, 68, 255, 31, 244, 63, 247, 0, 63, 247, 127, 192, 207, 134, 255, 48, 0, 255, 171, 248, 8, 252, 175, 240, 0, 12, 253, 255, 80, 79, 253, 252, 0, 0, 143, 255, 241, 0, 255, 255, 144, 0, 5, 255, 253, 0, 12, 255, 245, 0, 0, 31, 255, 144, 0, 143, 255, 16, 0, 0, 223, 245, 0, 4, 255, 224, 0 };
/* X */ static const uint8_t Font_Roboto_Bold_20_glyph_88[] = { 13, 14, 13, 0, 14, 111, 254, 0, 0, 63, 255, 32, 207, 248, 0, 12, 255, 112, 3, 255, 241, 5, 255, 208, 0, 9, 255, 144, 239, 244, 0, 0, 30, 255, 175, 251, 0, 0, 0, 111, 255, 255, 32, 0, 0, 0, 207, 255, 128, 0, 0, 0, 13, 255, 249, 0, 0, 0, 7, 255, 255, 243, 0, 0, 1, 255, 249, 255, 192, 0, 0, 175, 249, 13, 255, 96, 0, 79, 255, 16, 79, 254, 16, 13, 255, 112, 0, 191, 249, 7, 255, 208, 0, 3, 255, 243 };
/* Y */ static const uint8_t Font_Roboto_Bold_20_glyph_89[] = { 13, 14, 12, 0, 14, 191, 247, 0, 0, 47, 255, 19, 255, 224, 0, 9, 255, 128, 10, 255, 96, 1, 255, 241, 0, 47, 253, 0, 143, 248, 0, 0, 175, 245, 14, 254, 0, 0, 2, 255, 199, 255, 112, 0, 0, 9, 255, 255, 224, 0, 0, 0, 31, 255, 246, 0, 0, 0, 0, 143, 253, 0, 0, 0, 0, 5, 255, 160, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 5, 255, 160, 0, 0, 0, 0, 95, 250, 0, 0, 0, 0, 5, 255, 160, 0, 0 };
/* Z */ static const uint8_t Font_Roboto_Bold_20_glyph_90[] = { 12, 14, 12, 0, 14, 79, 255, 255, 255, 255, 246, 79, 255, 255, 255, 255, 245, 22, 102, 102, 106, 255, 192, 0, 0, 0, 30, 255, 32, 0, 0, 0, 191, 246, 0, 0, 0, 7, 255, 176, 0, 0, 0, 63, 254, 16, 0, 0, 0, 223, 244, 0, 0, 0, 9, 255, 144, 0, 0, 0, 79, 253, 0, 0, 0, 1, 239, 243, 0, 0, 0, 11, 255, 181, 85, 85, 83, 79, 255, 255, 255, 255, 248, 79, 255, 255, 255, 255, 248 };
/* [ */ static const uint8_t Font_Roboto_Bold_20_glyph_91[] = { 5, 20, 6, 1, 17, 223, 255, 109, 255, 246, 223, 242, 29, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 0, 223, 240, 13, 255, 33, 223, 255, 109, 255, 246 };
/* \ */ static const uint8_t Font_Roboto_Bold_20_glyph_92[] = { 9, 15, 8, 0, 14, 207, 241, 0, 0, 6, 255, 112, 0, 0, 15, 253, 0, 0, 0, 159, 244, 0, 0, 3, 255, 160, 0, 0, 13, 255, 16, 0, 0, 111, 247, 0, 0, 1, 255, 208, 0, 0, 10, 255, 48, 0, 0, 79, 250, 0, 0, 0, 223, 241, 0, 0, 7, 255, 96, 0, 0, 31, 253, 0, 0, 0, 175, 243, 0, 0, 4, 255, 144 };
/* ] */ static const uint8_t Font_Roboto_Bold_20_glyph_93[] = { 5, 20, 6, 0, 17, 239, 255, 94, 255, 245, 40, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 80, 127, 245, 7, 255, 82, 143, 245, 239, 255, 94, 255, 245 };
/* ^ */ static const uint8_t Font_Roboto_Bold_20_glyph_94[] = { 9, 7, 9, 0, 14, 0, 11, 251, 0, 0, 2, 255, 242, 0, 0, 159, 255, 144, 0, 15, 245, 255, 0, 6, 252, 12, 246, 0, 223, 96, 111, 208, 63, 240, 0, 255, 48 };
/* _ */ static const uint8_t Font_Roboto_Bold_20_glyph_95[] = { 9, 3, 9, 0, 0, 255, 255, 255, 255, 239, 255, 255, 255, 254, 51, 51, 51, 51, 32 };
/* ` */ static const uint8_t Font_Roboto_Bold_20_glyph_96[] = { 6, 3, 7, 0, 15, 46, 253, 0, 3, 255, 128, 0, 79, 243 };
/* a */ static const uint8_t Font_Roboto_Bold_20_glyph_97[] = { 11, 11, 11, 0, 11, 0, 75, 239, 216, 16, 0, 127, 255, 255, 253, 0, 15, 254, 50, 159, 246, 0, 0, 0, 3, 255, 144, 0, 108, 239, 255, 250, 0, 159, 254, 187, 255, 160, 47, 252, 0, 63, 250, 4, 255, 128, 3, 255, 160, 63, 253, 52, 223, 250, 0, 207, 255, 255, 255, 176, 0, 142, 252, 62, 254, 0 };
/* b */ static const uint8_t Font_Roboto_Bold_20_glyph_98[] = { 11, 15, 11, 0, 15, 31, 252, 0, 0, 0, 1, 255, 192, 0, 0, 0, 31, 252, 0, 0, 0, 1, 255, 192, 0, 0, 0, 31, 252, 126, 253, 80, 1, 255, 255, 255, 255, 80, 31, 255, 149, 159, 254, 1, 255, 208, 0, 191, 244, 31, 252, 0, 7, 255, 97, 255, 192, 0, 111, 247, 31, 252, 0, 6, 255, 97, 255, 208, 0, 175, 244, 31, 255, 149, 143, 254, 1, 255, 255, 255, 255, 96, 31, 249, 142, 253, 80, 0 };
/* c */ static const uint8_t Font_Roboto_Bold_20_glyph_99[] = { 10, 11, 10, 0, 11, 0, 59, 239, 216, 0, 4, 255, 255, 255, 176, 14, 255, 117, 207, 245, 95, 248, 0, 31, 249, 143, 245, 0, 2, 33, 159, 244, 0, 0, 0, 143, 245, 0, 0, 0, 95, 248, 0, 29, 216, 14, 255, 117, 191, 246, 4, 255, 255, 255, 176, 0, 59, 239, 215, 0 };
/* d */ static const uint8_t Font_Roboto_Bold_20_glyph_100[] = { 11, 15, 11, 0, 15, 0, 0, 0, 12, 255, 0, 0, 0, 0, 207, 240, 0, 0, 0, 12, 255, 0, 0, 0, 0, 207, 240, 0, 93, 253, 108, 255, 0, 95, 255, 255, 255, 240, 14, 255, 149, 175, 255, 4, 255, 176, 0, 223, 240, 111, 246, 0, 13, 255, 7, 255, 80, 0, 223, 240, 111, 246, 0, 13, 255, 3, 255, 160, 0, 223, 240, 14, 255, 133, 175, 255, 0, 95, 255, 255, 255, 240, 0, 93, 254, 137, 255, 0 };
/* e */ static const uint8_t Font_Roboto_Bold_20_glyph_101[] = { 11, 11, 11, 0, 11, 0, 7, 223, 235, 48, 0, 11, 255, 255, 255, 80, 7, 255, 165, 110, 254, 0, 239, 208, 0, 127, 243, 31, 255, 255, 255, 255, 83, 255, 254, 238, 238, 229, 47, 252, 0, 0, 0, 0, 239, 243, 0, 6, 32, 8, 255, 231, 89, 253, 0, 11, 255, 255, 255, 144, 0, 6, 207, 252, 80, 0 };
/* f */ static const uint8_t Font_Roboto_Bold_20_glyph_102[] = { 8, 15, 7, 0, 15, 0, 8, 223, 225, 0, 191, 255, 241, 2, 255, 230, 80, 3, 255, 144, 0, 207, 255, 255, 176, 207, 255, 255, 176, 4, 255, 161, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0, 3, 255, 144, 0 };
/* g */ static const uint8_t Font_Roboto_Bold_20_glyph_103[] = { 11, 15, 11, 0, 11, 0, 76, 254, 169, 255, 32, 95, 255, 255, 255, 242, 14, 255, 165, 159, 255, 36, 255, 176, 0, 191, 242, 127, 246, 0, 11, 255, 40, 255, 80, 0, 191, 242, 127, 246, 0, 11, 255, 36, 255, 176, 0, 191, 242, 14, 255, 149, 159, 255, 32, 95, 255, 255, 255, 242, 0, 76, 254, 139, 255, 16, 2, 0, 0, 239, 240, 4, 248, 68, 191, 250, 0, 159, 255, 255, 253, 16, 0, 92, 255, 216, 0, 0 };
/* h */ static const uint8_t Font_Roboto_Bold_20_glyph_104[] = { 11, 15, 11, 0, 15, 31, 251, 0, 0, 0, 1, 255, 176, 0, 0, 0, 31, 251, 0, 0, 0, 1, 255, 176, 0, 0, 0, 31, 251, 93, 254, 112, 1, 255, 239, 255, 255, 96, 31, 255, 149, 159, 253, 1, 255, 192, 0, 223, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 0 };
/* i */ static const uint8_t Font_Roboto_Bold_20_glyph_105[] = { 5, 15, 5, 0, 15, 8, 232, 0, 255, 240, 9, 250, 0, 0, 0, 14, 254, 0, 239, 224, 14, 254, 0, 239, 224, 14, 254, 0, 239, 224, 14, 254, 0, 239, 224, 14, 254, 0, 239, 224, 14, 254, 0 };
/* j */ static const uint8_t Font_Roboto_Bold_20_glyph_106[] = { 6, 19, 5, -1, 15, 0, 142, 128, 0, 255, 240, 0, 159, 160, 0, 0, 0, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 223, 240, 0, 239, 240, 88, 255, 192, 255, 255, 80, 239, 214, 0 };
/* k */ static const uint8_t Font_Roboto_Bold_20_glyph_107[] = { 10, 15, 11, 1, 15, 239, 224, 0, 0, 0, 239, 224, 0, 0, 0, 239, 224, 0, 0, 0, 239, 224, 0, 0, 0, 239, 224, 4, 255, 242, 239, 224, 46, 255, 64, 239, 224, 223, 247, 0, 239, 235, 255, 160, 0, 239, 255, 254, 0, 0, 239, 255, 255, 80, 0, 239, 254, 255, 225, 0, 239, 242, 143, 249, 0, 239, 224, 13, 255, 64, 239, 224, 4, 255, 208, 239, 224, 0, 175, 248 };
/* l */ static const uint8_t Font_Roboto_Bold_20_glyph_108[] = { 4, 15, 5, 1, 15, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241, 207, 241 };
/* m */ static const uint8_t Font_Roboto_Bold_20_glyph_109[] = { 17, 11, 17, 0, 11, 31, 249, 92, 254, 112, 92, 254, 128, 1, 255, 239, 255, 255, 191, 255, 255, 128, 31, 255, 149, 159, 255, 181, 143, 254, 1, 255, 192, 0, 255, 240, 0, 223, 240, 31, 252, 0, 14, 254, 0, 12, 255, 17, 255, 192, 0, 239, 224, 0, 207, 241, 31, 252, 0, 14, 254, 0, 12, 255, 17, 255, 192, 0, 239, 224, 0, 207, 241, 31, 252, 0, 14, 254, 0, 12, 255, 17, 255, 192, 0, 239, 224, 0, 207, 241, 31, 252, 0, 14, 254, 0, 12, 255, 16 };
/* n */ static const uint8_t Font_Roboto_Bold_20_glyph_110[] = { 11, 11, 11, 0, 11, 31, 249, 109, 254, 128, 1, 255, 255, 255, 255, 96, 31, 255, 149, 143, 253, 1, 255, 192, 0, 223, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 1, 255, 176, 0, 207, 240, 31, 251, 0, 12, 255, 0 };
/* o */ static const uint8_t Font_Roboto_Bold_20_glyph_111[] = { 11, 11, 11, 0, 11, 0, 25, 239, 233, 16, 0, 46, 255, 255, 254, 32, 13, 255, 149, 159, 253, 3, 255, 176, 0, 191, 243, 111, 246, 0, 6, 255, 104, 255, 80, 0, 95, 247, 127, 246, 0, 6, 255, 99, 255, 176, 0, 191, 243, 13, 255, 149, 159, 253, 0, 62, 255, 255, 254, 32, 0, 42, 239, 233, 32, 0 };
/* p */ static const uint8_t Font_Roboto_Bold_20_glyph_112[] = { 11, 15, 11, 0, 11, 31, 250, 142, 253, 80, 1, 255, 255, 255, 255, 80, 31, 255, 149, 159, 254, 1, 255, 192, 0, 191, 243, 31, 252, 0, 7, 255, 97, 255, 192, 0, 111, 247, 31, 252, 0, 7, 255, 97, 255, 192, 0, 191, 243, 31, 255, 149, 159, 254, 1, 255, 255, 255, 255, 80, 31, 252, 126, 253, 80, 1, 255, 192, 0, 0, 0, 31, 252, 0, 0, 0, 1, 255, 192, 0, 0, 0, 31, 252, 0, 0, 0, 0 };
/* q */ static const uint8_t Font_Roboto_Bold_20_glyph_113[] = { 11, 15, 11, 0, 11, 0, 93, 254, 136, 255, 0, 111, 255, 255, 255, 240, 14, 255, 149, 175, 255, 4, 255, 176, 0, 223, 240, 127, 246, 0, 13, 255, 7, 255, 80, 0, 223, 240, 111, 246, 0, 13, 255, 4, 255, 176, 0, 223, 240, 14, 255, 149, 159, 255, 0, 95, 255, 255, 255, 240, 0, 93, 254, 125, 255, 0, 0, 0, 0, 223, 240, 0, 0, 0, 13, 255, 0, 0, 0, 0, 223, 240, 0, 0, 0, 13, 255, 0 };
/* r */ static const uint8_t Font_Roboto_Bold_20_glyph_114[] = { 7, 11, 7, 0, 11, 31, 249, 126, 209, 255, 239, 254, 31, 255, 252, 177, 255, 226, 0, 31, 252, 0, 1, 255, 192, 0, 31, 252, 0, 1, 255, 192, 0, 31, 252, 0, 1, 255, 192, 0, 31, 252, 0, 0 };
/* s */ static const uint8_t Font_Roboto_Bold_20_glyph_115[] = { 10, 11, 10, 0, 11, 0, 92, 238, 198, 0, 9, 255, 255, 255, 160, 47, 251, 17, 207, 243, 63, 249, 0, 54, 98, 14, 255, 216, 64, 0, 2, 207, 255, 254, 64, 0, 3, 140, 255, 241, 73, 145, 0, 143, 245, 95, 249, 17, 175, 244, 11, 255, 255, 255, 192, 0, 124, 255, 198, 0 };
/* t */ static const uint8_t Font_Roboto_Bold_20_glyph_116[] = { 7, 14, 7, 0, 14, 3, 255, 160, 0, 63, 250, 0, 3, 255, 160, 12, 255, 255, 246, 207, 255, 255, 96, 79, 250, 16, 3, 255, 160, 0, 63, 250, 0, 3, 255, 160, 0, 63, 250, 0, 3, 255, 160, 0, 31, 254, 83, 0, 223, 255, 128, 2, 191, 246 };
/* u */ static const uint8_t Font_Roboto_Bold_20_glyph_117[] = { 11, 11, 11, 0, 11, 31, 252, 0, 12, 255, 1, 255, 192, 0, 207, 240, 31, 252, 0, 12, 255, 1, 255, 192, 0, 207, 240, 31, 252, 0, 12, 255, 1, 255, 192, 0, 207, 240, 31, 252, 0, 12, 255, 0, 255, 208, 0, 223, 240, 13, 255, 133, 159, 255, 0, 127, 255, 255, 255, 240, 0, 125, 253, 106, 255, 0 };
/* v */ static const uint8_t Font_Roboto_Bold_20_glyph_118[] = { 10, 11, 10, 0, 11, 207, 242, 0, 63, 251, 127, 246, 0, 127, 246, 47, 250, 0, 191, 241, 12, 254, 0, 255, 192, 7, 255, 52, 255, 96, 2, 255, 120, 255, 16, 0, 223, 188, 252, 0, 0, 143, 255, 247, 0, 0, 47, 255, 242, 0, 0, 13, 255, 192, 0, 0, 8, 255, 112, 0 };
/* w */ static const uint8_t Font_Roboto_Bold_20_glyph_119[] = { 15, 11, 15, 0, 11, 127, 243, 0, 191, 144, 4, 255, 99, 255, 96, 15, 254, 0, 143, 242, 15, 250, 3, 255, 242, 11, 254, 0, 191, 208, 143, 255, 112, 239, 160, 7, 255, 12, 252, 251, 31, 246, 0, 63, 244, 255, 63, 245, 255, 32, 0, 255, 207, 192, 223, 207, 224, 0, 11, 255, 247, 8, 255, 250, 0, 0, 143, 255, 48, 79, 255, 112, 0, 4, 255, 224, 0, 255, 243, 0, 0, 15, 249, 0, 10, 255, 0, 0 };
/* x */ static const uint8_t Font_Roboto_Bold_20_glyph_120[] = { 11, 11, 10, 0, 11, 111, 250, 0, 111, 249, 0, 223, 242, 14, 255, 16, 4, 255, 183, 255, 128, 0, 11, 255, 255, 224, 0, 0, 47, 255, 246, 0, 0, 0, 207, 255, 0, 0, 0, 79, 255, 248, 0, 0, 13, 255, 239, 241, 0, 6, 255, 149, 255, 160, 0, 239, 241, 12, 255, 48, 143, 248, 0, 79, 251, 0 };
/* y */ static const uint8_t Font_Roboto_Bold_20_glyph_121[] = { 10, 15, 10, 0, 11, 223, 243, 0, 47, 253, 127, 247, 0, 127, 247, 47, 252, 0, 207, 242, 12, 255, 17, 255, 192, 6, 255, 101, 255, 112, 1, 255, 170, 255, 16, 0, 191, 254, 252, 0, 0, 111, 255, 246, 0, 0, 31, 255, 241, 0, 0, 11, 255, 176, 0, 0, 6, 255, 96, 0, 0, 9, 255, 16, 0, 4, 127, 250, 0, 0, 13, 255, 242, 0, 0, 12, 252, 64, 0, 0 };
/* z */ static const uint8_t Font_Roboto_Bold_20_glyph_122[] = { 10, 11, 10, 0, 11, 47, 255, 255, 255, 245, 47, 255, 255, 255, 244, 4, 68, 75, 255, 176, 0, 0, 63, 254, 16, 0, 0, 223, 245, 0, 0, 9, 255, 144, 0, 0, 79, 253, 0, 0, 1, 239, 243, 0, 0, 11, 255, 180, 68, 66, 79, 255, 255, 255, 248, 79, 255, 255, 255, 248 };
/* { */ static const uint8_t Font_Roboto_Bold_20_glyph_123[] = { 7, 20, 7, 0, 16, 0, 0, 92, 16, 0, 143, 244, 0, 47, 247, 0, 7, 255, 0, 0, 159, 240, 0, 10, 254, 0, 0, 175, 224, 0, 11, 253, 0, 4, 255, 128, 5, 255, 192, 0, 95, 251, 0, 0, 79, 248, 0, 0, 191, 208, 0, 10, 254, 0, 0, 175, 224, 0, 9, 255, 0, 0, 127, 241, 0, 2, 255, 112, 0, 7, 255, 64, 0, 5, 193 };
/* | */ static const uint8_t Font_Roboto_Bold_20_glyph_124[] = { 3, 17, 5, 1, 14, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 101, 246, 95, 96 };
/* } */ static const uint8_t Font_Roboto_Bold_20_glyph_125[] = { 7, 20, 7, 0, 16, 28, 80, 0, 4, 255, 112, 0, 7, 255, 32, 0, 31, 247, 0, 0, 255, 144, 0, 14, 249, 0, 0, 239, 144, 0, 13, 251, 0, 0, 143, 243, 0, 0, 207, 245, 0, 11, 255, 80, 8, 255, 64, 0, 223, 176, 0, 14, 249, 0, 0, 239, 144, 0, 15, 249, 0, 1, 255, 112, 0, 127, 242, 0, 79, 247, 0, 1, 197, 0, 0 };
/* ~ */ static const uint8_t Font_Roboto_Bold_20_glyph_126[] = { 11, 5, 13, 1, 8, 6, 239, 195, 0, 42, 149, 255, 255, 246, 9, 252, 207, 198, 207, 255, 255, 109, 227, 0, 143, 255, 160, 0, 0, 0, 20, 32, 0 };

const uint8_t * const Font_Roboto_Bold_20[126 + 1 - 32] = {
    Font_Roboto_Bold_20_glyph_32,
    Font_Roboto_Bold_20_glyph_33,
    Font_Roboto_Bold_20_glyph_34,
    Font_Roboto_Bold_20_glyph_35,
    Font_Roboto_Bold_20_glyph_36,
    Font_Roboto_Bold_20_glyph_37,
    Font_Roboto_Bold_20_glyph_38,
    Font_Roboto_Bold_20_glyph_39,
    Font_Roboto_Bold_20_glyph_40,
    Font_Roboto_Bold_20_glyph_41,
    Font_Roboto_Bold_20_glyph_42,
    Font_Roboto_Bold_20_glyph_43,
    Font_Roboto_Bold_20_glyph_44,
    Font_Roboto_Bold_20_glyph_45,
    Font_Roboto_Bold_20_glyph_46,
    Font_Roboto_Bold_20_glyph_47,
    Font_Roboto_Bold_20_glyph_48,
    Font_Roboto_Bold_20_glyph_49,
    Font_Roboto_Bold_20_glyph_50,
    Font_Roboto_Bold_20_glyph_51,
    Font_Roboto_Bold_20_glyph_52,
    Font_Roboto_Bold_20_glyph_53,
    Font_Roboto_Bold_20_glyph_54,
    Font_Roboto_Bold_20_glyph_55,
    Font_Roboto_Bold_20_glyph_56,
    Font_Roboto_Bold_20_glyph_57,
    Font_Roboto_Bold_20_glyph_58,
    Font_Roboto_Bold_20_glyph_59,
    Font_Roboto_Bold_20_glyph_60,
    Font_Roboto_Bold_20_glyph_61,
    Font_Roboto_Bold_20_glyph_62,
    Font_Roboto_Bold_20_glyph_63,
    Font_Roboto_Bold_20_glyph_64,
    Font_Roboto_Bold_20_glyph_65,
    Font_Roboto_Bold_20_glyph_66,
    Font_Roboto_Bold_20_glyph_67,
    Font_Roboto_Bold_20_glyph_68,
    Font_Roboto_Bold_20_glyph_69,
    Font_Roboto_Bold_20_glyph_70,
    Font_Roboto_Bold_20_glyph_71,
    Font_Roboto_Bold_20_glyph_72,
    Font_Roboto_Bold_20_glyph_73,
    Font_Roboto_Bold_20_glyph_74,
    Font_Roboto_Bold_20_glyph_75,
    Font_Roboto_Bold_20_glyph_76,
    Font_Roboto_Bold_20_glyph_77,
    Font_Roboto_Bold_20_glyph_78,
    Font_Roboto_Bold_20_glyph_79,
    Font_Roboto_Bold_20_glyph_80,
    Font_Roboto_Bold_20_glyph_81,
    Font_Roboto_Bold_20_glyph_82,
    Font_Roboto_Bold_20_glyph_83,
    Font_Roboto_Bold_20_glyph_84,
    Font_Roboto_Bold_20_glyph_85,
    Font_Roboto_Bold_20_glyph_86,
    Font_Roboto_Bold_20_glyph_87,
    Font_Roboto_Bold_20_glyph_88,
    Font_Roboto_Bold_20_glyph_89,
    Font_Roboto_Bold_20_glyph_90,
    Font_Roboto_Bold_20_glyph_91,
    Font_Roboto_Bold_20_glyph_92,
    Font_Roboto_Bold_20_glyph_93,
    Font_Roboto_Bold_20_glyph_94,
    Font_Roboto_Bold_20_glyph_95,
    Font_Roboto_Bold_20_glyph_96,
    Font_Roboto_Bold_20_glyph_97,
    Font_Roboto_Bold_20_glyph_98,
    Font_Roboto_Bold_20_glyph_99,
    Font_Roboto_Bold_20_glyph_100,
    Font_Roboto_Bold_20_glyph_101,
    Font_Roboto_Bold_20_glyph_102,
    Font_Roboto_Bold_20_glyph_103,
    Font_Roboto_Bold_20_glyph_104,
    Font_Roboto_Bold_20_glyph_105,
    Font_Roboto_Bold_20_glyph_106,
    Font_Roboto_Bold_20_glyph_107,
    Font_Roboto_Bold_20_glyph_108,
    Font_Roboto_Bold_20_glyph_109,
    Font_Roboto_Bold_20_glyph_110,
    Font_Roboto_Bold_20_glyph_111,
    Font_Roboto_Bold_20_glyph_112,
    Font_Roboto_Bold_20_glyph_113,
    Font_Roboto_Bold_20_glyph_114,
    Font_Roboto_Bold_20_glyph_115,
    Font_Roboto_Bold_20_glyph_116,
    Font_Roboto_Bold_20_glyph_117,
    Font_Roboto_Bold_20_glyph_118,
    Font_Roboto_Bold_20_glyph_119,
    Font_Roboto_Bold_20_glyph_120,
    Font_Roboto_Bold_20_glyph_121,
    Font_Roboto_Bold_20_glyph_122,
    Font_Roboto_Bold_20_glyph_123,
    Font_Roboto_Bold_20_glyph_124,
    Font_Roboto_Bold_20_glyph_125,
    Font_Roboto_Bold_20_glyph_126,
};
