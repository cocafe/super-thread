#ifndef SUPER_THREAD_GUI_H
#define SUPER_THREAD_GUI_H

#include <pthread.h>

extern pthread_t profile_wnd_tid;

int gui_profile_wnd_create(void);

void gui_init(void);
void gui_deinit(void);

#endif // SUPER_THREAD_GUI_H