#ifndef SUPER_THREAD_H_
#define SUPER_THREAD_H_

#include "tray.h"
#include "jkey.h"
#include "config_opts.h"

extern struct tray g_tray;
extern uint32_t g_should_exit;
extern optdesc_t *g_opt_list[];
extern jbuf_t jbuf_usrcfg;

int superthread_tray_init(HINSTANCE ins);
void superthread_tray_deinit(void);
int superthread_quit(void);

#endif // SUPER_THREAD_H_