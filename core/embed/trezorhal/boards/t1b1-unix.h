#ifndef BOARDS_T1B1_UNIX_H
#define BOARDS_T1B1_UNIX_H

#define USE_BUTTON 1

#define MAX_DISPLAY_RESX 128
#define MAX_DISPLAY_RESY 64
#define DISPLAY_RESX 128
#define DISPLAY_RESY 64
#define TREZOR_FONT_BPP 1

#define WINDOW_WIDTH 200
#define WINDOW_HEIGHT 340
#define TOUCH_OFFSET_X 36
#define TOUCH_OFFSET_Y 92

#define ORIENTATION_NS 1

#define BACKGROUND_FILE "background_1.h"
#define BACKGROUND_NAME background_1_jpg

#include "display-unix.h"

#endif  // BOARDS_T1B1_UNIX_H
