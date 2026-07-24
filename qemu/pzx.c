#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "hw/char/pl011.h"
#include "hw/loader.h"
#include "hw/qdev-properties.h"
#include "target/arm/cpu.h"
#include "sysemu/sysemu.h"

#define TYPE_PZX_MACHINE MACHINE_TYPE_NAME("pzx")
OBJECT_DECLARE_SIMPLE_TYPE(PzxMachineState, PZX_MACHINE)

struct PzxMachineState {
    MachineState parent;

    ARMCPU *cpu;
    MemoryRegion mrom;  // store bootcode
    MemoryRegion dram;
};

enum {
    ID_MROM = 0,
    ID_SRAM,
    ID_UART,
    ID_DRAM,
};

static const MemMapEntry pzx_memmap[] = {
    [ID_MROM] = { 0x00000000, 0x00080000 },
    [ID_SRAM] = { 0x00080000, 0x00280000 },
    [ID_UART] = { 0x00300000, 0x00001000 },
    [ID_DRAM] = { 0x80000000, 0x08000000 },
};

unsigned char bootcode[] = {
  0x80, 0x01, 0x00, 0x58, 0xe1, 0x00, 0x00, 0x10, 0x22, 0x14, 0x40, 0x38,
  0x62, 0x00, 0x00, 0x34, 0x02, 0x00, 0x00, 0xb9, 0xfd, 0xff, 0xff, 0x17,
  0x5f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0x17, 0x48, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00
};


static void pzx_machine_init(MachineState *machine)
{
    PzxMachineState *state = PZX_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();

    state->cpu = ARM_CPU(object_new(ARM_CPU_TYPE_NAME("cortex-a53")));
    object_property_set_bool(OBJECT(state->cpu), "aarch64", true,  &error_fatal);
    qdev_realize(DEVICE(state->cpu), NULL, &error_fatal);

    memory_region_init_rom(&state->mrom, OBJECT(machine), "pzx.mrom",
            pzx_memmap[ID_MROM].size, &error_fatal);
    memory_region_add_subregion(sysmem, pzx_memmap[ID_MROM].base, &state->mrom);

    memory_region_init_ram(&state->dram, OBJECT(machine), "pzx.dram",
            pzx_memmap[ID_DRAM].size, &error_fatal);
    memory_region_add_subregion(sysmem, pzx_memmap[ID_DRAM].base, &state->dram);

    DeviceState *pl011 = qdev_new(TYPE_PL011);
    qdev_prop_set_chr(pl011, "chardev", serial_hd(0));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(pl011), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(pl011), 0, pzx_memmap[ID_UART].base);

    rom_add_blob_fixed("bootcode", bootcode, sizeof(bootcode), pzx_memmap[ID_MROM].base);
}

static void pzx_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "pzx.arm64.machine";
    mc->init = pzx_machine_init;
    mc->default_ram_size = 128 * MiB;
}

static const TypeInfo pzx_machine_type_info = {
    .name = TYPE_PZX_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(PzxMachineState),
    .class_init = pzx_machine_class_init,
};

static void pzx_machine_register_type(void)
{
    type_register_static(&pzx_machine_type_info);
}
type_init(pzx_machine_register_type)
