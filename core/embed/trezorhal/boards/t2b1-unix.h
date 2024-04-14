#ifndef BOARDS_T2B1_UNIX_H
#define BOARDS_T2B1_UNIX_H

#define USE_BUTTON 1
#define USE_SBU 1
#define USE_OPTIGA 1

#define MAX_DISPLAY_RESX 128
#define MAX_DISPLAY_RESY 64
#define DISPLAY_RESX 128
#define DISPLAY_RESY 64
#define TREZOR_FONT_BPP 1

#define WINDOW_WIDTH 193
#define WINDOW_HEIGHT 339
#define TOUCH_OFFSET_X 32
#define TOUCH_OFFSET_Y 84

#define ORIENTATION_NS 1

#define BACKGROUND_FILE "background_T2B1.h"
#define BACKGROUND_NAME background_T2B1_jpg

#include "display-unix.h"

#endif  // BOARDS_T2B1_UNIX_H
