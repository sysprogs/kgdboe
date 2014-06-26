#pragma once

int kgdboe_io_init(const char *device_name, int port, const char *local_ip, bool force_single_core);
void kgdboe_io_cleanup(void);