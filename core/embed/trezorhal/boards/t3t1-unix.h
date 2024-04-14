#ifndef BOARDS_T3T1_UNIX_H
#define BOARDS_T3T1_UNIX_H

#define USE_TOUCH 1
#define USE_SD_CARD 1
#define USE_SBU 1
#define USE_RGB_COLORS 1
#define USE_BACKLIGHT 1
#define USE_OPTIGA 1

#define MAX_DISPLAY_RESX 240
#define MAX_DISPLAY_RESY 240
#define DISPLAY_RESX 240
#define DISPLAY_RESY 240
#define TREZOR_FONT_BPP 4

#define WINDOW_WIDTH 400
#define WINDOW_HEIGHT 600
#define TOUCH_OFFSET_X 80
#define TOUCH_OFFSET_Y 110

#define ORIENTATION_NSEW 1

#define BACKGROUND_FILE "background_T.h"
#define BACKGROUND_NAME background_T_jpg

#include "display-unix.h"

#endif  // BOARDS_T3T1_UNIX_H
