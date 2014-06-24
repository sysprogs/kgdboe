#pragma once

void take_hooked_spinlocks();
void save_hooked_spinlocks();
void restore_hooked_spinlocks();
void release_hooked_spinlocks();

void hold_irq_enabling();
void enable_queued_irqs();