import ctypes
from ida_idd import dbg_read_memory, modinfo_t
from ctypes import c_void_p, c_uint32
from typing import Type, TypeVar
from ida_dbg import DSTATE_SUSP, DBG_Hooks, add_virt_module, get_process_state, write_dbg_memory, read_dbg_memory, refresh_debugger_memory
from idc import get_name_ea_simple, set_bpt_cond, add_bpt
from ida_idaapi import BADADDR
from ida_kernwin import UI_Hooks

if not hasattr(ctypes, '_CData'):
    print("polyfilling _CData")
    class _CData:
        pass
    setattr(ctypes, '_CData', _CData)

class JitCodeEntry(ctypes.Structure):
    _fields_ = [
        ("next", c_void_p),
        ("prev", c_void_p),
        ("symfile_addr", c_void_p),
        ("symfile_size", c_void_p),
    ]
class JitDescriptor(ctypes.Structure):
    _fields_ = [
        ("version", c_uint32),
        ("action_flag", c_uint32),
        ("relevant_entry", c_void_p),
    ]

R = TypeVar('R', bound=ctypes._CData)
def read_memory(addr, ty: Type[R]) -> R:
    result = dbg_read_memory(addr, ctypes.sizeof(ty))
    if len(result) != ctypes.sizeof(ty):
        raise Exception("memory read didn't succeed")
    return ty.from_buffer_copy(result)
def write_memory(addr: int, value: ctypes._CData):
    data = ctypes.string_at(ctypes.addressof(value), ctypes.sizeof(value))
    if not write_dbg_memory(int(addr), data, ctypes.sizeof(value)):
        print(f"memory write failed, ignoring")

def define_module(entry: JitCodeEntry):
    m = modinfo_t()
    m.base = entry.symfile_addr
    m.size = entry.symfile_size
    m.name = f"JitFile.{hex(entry.symfile_addr)}"
    add_virt_module(m)

def read_jit_debug_descriptor(first: bool):
    if get_process_state() != DSTATE_SUSP:
        print("debugger is not running or not suspended")
        return

    # We may have outdated memory after direct breakpoint hit, flush the caches.
    # TODO: Maybe flush cache partially in `def read_memory`?
    refresh_debugger_memory()

    descriptor_addr = get_name_ea_simple("__jit_debug_descriptor")
    if descriptor_addr == BADADDR:
        print("__jit_debug_descriptor not found")
        return

    jit_desc = read_memory(descriptor_addr, JitDescriptor)
    if jit_desc.version != 1:
        print("unknown JIT descriptor version?")

    print(f"processing jit descriptor, action={jit_desc.action_flag}")
    if jit_desc.action_flag == 0:
        # No action
        pass
    elif jit_desc.action_flag == 1:
        # Add
        entry = read_memory(jit_desc.relevant_entry, JitCodeEntry)
        define_module(entry)
        if first:
            while entry.prev != None:
                entry = read_memory(entry.prev, JitCodeEntry)
                define_module(entry)
    elif jit_desc.action_flag == 2:
        # Remove
        print("jit remove is not implemented")
    else:
        print(f"unknown action: {jit_desc.action_flag}")
    write_memory(descriptor_addr + JitDescriptor.action_flag.offset, c_uint32(0))

def register_bp():
    register_fn = get_name_ea_simple("__jit_debug_register_code")

    if register_fn == BADADDR:
        print("jit registration not found")
        return None

    # In case we missed breakpoint already
    read_jit_debug_descriptor(True)
    if not add_bpt(register_fn):
        print("bpt registration failed")
    print("registered jit breakpoint")

    return register_fn

class Handler(DBG_Hooks):
    def __init__(self):
        DBG_Hooks.__init__(self)
        self.register_fn = None

    def dbg_bpt(self, tid, ea) -> int:
        if ea == self.register_fn:
            print(f"debug registration hit")
            read_jit_debug_descriptor(False)
            return 0
        return super().dbg_bpt(tid, ea)

    def dbg_process_start(self, *args):
        self.register_fn = register_bp()
    def dbg_process_attach(self, *args):
        self.register_fn = register_bp()

try:
    if debughook:
        print("Uninstalling prev hook")
        debughook.unhook()
    del debughook
except:
    pass
debughook = Handler()
debughook.hook()

class DbInsertHook(UI_Hooks):
    def __init__(self):
        UI_Hooks.__init__(self)
    def finish_populating_widget_popup(self, widget, popup, ctx):
        print(ctx)
        print(ctx.widget_title)
try:
    if uihook:
        print("Uninstalling prev hook")
        uihook.unhook()
except:
    pass
uihook = DbInsertHook()
uihook.hook()
