
import json, shlex, struct, gdb


def _ok(tool, args, data, structured=True):
    return {"ok": True, "tool": tool, "args": args, "structured": structured, "data": data}


def _err(tool, args, err):
    return {
        "ok": False,
        "tool": tool,
        "args": args,
        "error": {"type": type(err).__name__, "message": str(err)},
    }


def _parse_args(args):
    if args is None:
        return []
    if isinstance(args, (list, tuple)):
        return list(args)
    if not args:
        return []
    return shlex.split(args)


def _get_file():
    return gdb.current_progspace().filename or get_filepath()


def _to_hex(value):
    try:
        return hex(int(value))
    except Exception:
        return None


def _safe_int(value, default=None):
    try:
        return int(value, 0)
    except Exception:
        try:
            return int(value)
        except Exception:
            return default


def _pop_flag(argv, *names):
    for name in names:
        if name in argv:
            argv.remove(name)
            return True
    return False


def _pop_value(argv, *names, default=None):
    for name in names:
        if name in argv:
            idx = argv.index(name)
            if idx + 1 >= len(argv):
                raise Exception(f"Missing value for {name}")
            val = argv[idx + 1]
            del argv[idx : idx + 2]
            return val
    return default


def _normalize_reg(reg):
    if reg.startswith("$"):
        return reg
    if reg in gef.arch.all_registers:
        return f"${reg}"
    return reg


def _chunk_flags(chunk):
    return {
        "prev_inuse": chunk.has_p_bit(),
        "is_mmapped": chunk.has_m_bit(),
        "non_main_arena": chunk.has_n_bit(),
    }


def _chunk_to_dict(chunk):
    return {
        "base_address": _to_hex(chunk.base_address),
        "data_address": _to_hex(chunk.data_address),
        "size": chunk.size,
        "prev_size": chunk.prev_size,
        "usable_size": chunk.usable_size,
        "flags": _chunk_flags(chunk),
        "is_used": chunk.is_used(),
        "fd": _to_hex(chunk.fd),
        "bk": _to_hex(chunk.bk),
        "fd_nextsize": _to_hex(chunk.fd_nextsize),
        "bk_nextsize": _to_hex(chunk.bk_nextsize),
        "next_chunk": _to_hex(chunk.get_next_chunk_addr()),
    }


def _arena_to_dict(arena):
    return {
        "address": _to_hex(arena.addr),
        "top": _to_hex(arena.top),
        "last_remainder": _to_hex(arena.last_remainder),
        "next": _to_hex(arena.next),
        "system_mem": int(arena.system_mem),
        "max_system_mem": int(arena.max_system_mem),
        "is_main": arena.is_main_arena(),
    }


def _hexdump_bytes(addr, data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        ascii_str = "".join([chr(b) if 0x20 <= b < 0x7F else "." for b in chunk])
        lines.append(
            {
                "address": _to_hex(addr + i),
                "offset": i,
                "bytes_hex": chunk.hex(),
                "ascii": ascii_str,
            }
        )
    return lines


def _hexdump_words(start_addr, length, arrange_as, offset=0):
    endianness = gef.arch.endianness
    formats = {
        "qword": ("Q", 8),
        "dword": ("I", 4),
        "word": ("H", 2),
    }
    formatter, width = formats[arrange_as]
    fmt_pack = f"{endianness!s}{formatter}"
    show_ascii = gef.config["hexdump.always_show_ascii"]
    lines = []
    i = 0
    while i < length:
        cur_addr = start_addr + (i + offset) * width
        mem = gef.memory.read(cur_addr, width)
        val = struct.unpack(fmt_pack, mem)[0]
        entry = {
            "address": _to_hex(cur_addr),
            "offset": (i + offset) * width,
            "value": int(val),
        }
        if show_ascii:
            entry["ascii"] = "".join([chr(b) if 0x20 <= b < 0x7F else "." for b in mem])
        lines.append(entry)
        i += 1
    return lines


def _hexdump_cmd(args):
    argv = list(args)
    fmt = None
    address = None
    size = None
    reverse = False
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-s", "--size"):
            if i + 1 >= len(argv):
                raise Exception("Missing size")
            size = _safe_int(argv[i + 1])
            i += 2
            continue
        if tok in ("-r", "--reverse"):
            reverse = True
            i += 1
            continue
        if fmt is None:
            fmt = tok
            i += 1
            continue
        if address is None:
            address = tok
            i += 1
            continue
        i += 1

    if fmt not in ("byte", "word", "dword", "qword"):
        raise Exception("Invalid hexdump format")

    target = address or "$sp"
    start_addr = align_address(parse_address(target))

    if fmt == "byte":
        read_len = size or 0x40
        mem = gef.memory.read(start_addr, read_len)
        lines = _hexdump_bytes(start_addr, mem, 16)
        if reverse:
            lines.reverse()
        return {
            "format": fmt,
            "address": _to_hex(start_addr),
            "size": read_len,
            "reverse": reverse,
            "lines": lines,
        }

    read_len = size or 0x10
    lines = _hexdump_words(start_addr, read_len, fmt, 0)
    if reverse:
        lines.reverse()
    return {
        "format": fmt,
        "address": _to_hex(start_addr),
        "size": read_len,
        "reverse": reverse,
        "lines": lines,
    }


def _xinfo_cmd(args):
    if not args:
        raise Exception("At least one address is required")
    results = []
    for sym in args:
        addr = align_address(parse_address(sym))
        addr_info = lookup_address(addr)
        item = {"address": _to_hex(addr), "valid": bool(addr_info.valid)}
        if not addr_info.valid:
            results.append(item)
            continue
        sect = addr_info.section
        info = addr_info.info
        if sect:
            item["section"] = {
                "start": _to_hex(sect.page_start),
                "end": _to_hex(sect.page_end),
                "size": sect.page_end - sect.page_start,
                "permissions": str(sect.permission),
                "path": sect.path,
                "offset": addr_info.value - sect.page_start,
                "inode": sect.inode,
            }
        if info:
            item["segment"] = {
                "name": info.name,
                "start": _to_hex(info.zone_start),
                "end": _to_hex(info.zone_end),
                "offset": addr_info.value - info.zone_start,
            }
        sym_info = gdb_get_location_from_symbol(addr)
        if sym_info:
            name, offset = sym_info
            item["symbol"] = {"name": name, "offset": int(offset)}
        results.append(item)
    return {"items": results}


def _xfiles_cmd(args):
    filter_by_file = args[0] if args and args[0] else None
    filter_by_name = args[1] if len(args) > 1 and args[1] else None
    entries = []
    for xfile in get_info_files():
        if filter_by_file:
            if filter_by_file not in xfile.filename:
                continue
            if filter_by_name and filter_by_name not in xfile.name:
                continue
        entries.append(
            {
                "start": _to_hex(xfile.zone_start),
                "end": _to_hex(xfile.zone_end),
                "name": xfile.name,
                "file": xfile.filename,
            }
        )
    return {"files": entries}


def _registers_cmd(args):
    regs = {}
    selected = args or list(gef.arch.all_registers)
    for reg in selected:
        name = reg.lstrip("$")
        reg_expr = _normalize_reg(reg)
        try:
            val = gdb.parse_and_eval(reg_expr)
            regs[name] = _to_hex(val) or str(val)
        except Exception:
            try:
                regs[name] = _to_hex(gef.arch.register(reg_expr))
            except Exception:
                regs[name] = None
    return {"registers": regs, "flags": gef.arch.flag_register_to_human()}


def _arch_cmd():
    return {
        "arch": str(gef.arch.arch),
        "mode": str(gef.arch.mode),
        "ptrsize": gef.arch.ptrsize,
        "endianness": str(gef.arch.endianness),
        "pc": _to_hex(gef.arch.pc),
        "sp": _to_hex(gef.arch.sp),
    }


def _eval_cmd(expr):
    if not expr:
        raise Exception("Missing expression")
    val = gdb.parse_and_eval(expr)
    out = {"expr": expr, "value": str(val)}
    try:
        intval = int(val)
        out["int"] = intval
        out["hex"] = hex(intval)
    except Exception:
        pass
    return out


def _memory_cmd(args):
    argv = list(args)
    if not argv or argv[0] == "list":
        watches = []
        for address, opt in sorted(gef.ui.watches.items()):
            watches.append(
                {"address": _to_hex(address), "size": opt[0], "format": opt[1]}
            )
        return {"watches": watches}

    sub = argv[0]
    if sub == "reset":
        gef.ui.watches.clear()
        return {"cleared": True, "watches": []}
    if sub == "watch":
        if len(argv) < 2:
            raise Exception("Missing address")
        addr = parse_address(argv[1])
        size = parse_address(argv[2]) if len(argv) > 2 else 0x10
        if len(argv) > 3:
            group = argv[3].lower()
        else:
            group = "dword" if gef.arch.ptrsize == 4 else "qword"
        if group not in ("qword", "dword", "word", "byte", "pointers"):
            raise Exception("Unexpected grouping")
        gef.ui.watches[addr] = (size, group)
        return _memory_cmd(["list"])
    if sub == "unwatch":
        if len(argv) < 2:
            raise Exception("Missing address")
        addr = parse_address(argv[1])
        removed = gef.ui.watches.pop(addr, None) is not None
        data = _memory_cmd(["list"])
        data["removed"] = removed
        return data
    raise Exception("Unknown memory subcommand")


def _heap_set_arena(argv):
    args = list(argv)
    if _pop_flag(args, "--reset"):
        gef.heap.reset_caches()
        return {"reset": True}
    if not args:
        return {
            "selected_arena": _to_hex(gef.heap.selected_arena.addr)
            if gef.heap.selected_arena
            else None,
            "main_arena": _to_hex(gef.heap.main_arena.addr)
            if gef.heap.main_arena
            else None,
        }
    new_addr = parse_address(args[0])
    new_arena = GlibcArena(f"*{new_addr:#x}")
    if new_arena in gef.heap.arenas:
        gef.heap.selected_arena = new_arena
    else:
        gef.heap.main_arena = new_arena
    return {
        "selected_arena": _to_hex(gef.heap.selected_arena.addr)
        if gef.heap.selected_arena
        else None,
        "main_arena": _to_hex(gef.heap.main_arena.addr)
        if gef.heap.main_arena
        else None,
    }


def _heap_chunk(argv):
    args = list(argv)
    allow_unaligned = _pop_flag(args, "--allow-unaligned")
    number = _safe_int(_pop_value(args, "--number", default="1"), 1)
    if not args:
        raise Exception("Missing chunk address")
    addr = parse_address(args[0])
    chunks = []
    current = GlibcChunk(addr, allow_unaligned=allow_unaligned)
    for _ in range(number):
        chunks.append(_chunk_to_dict(current))
        if current.size == 0:
            break
        next_addr = current.get_next_chunk_addr()
        if not Address(value=next_addr).valid:
            break
        nxt = current.get_next_chunk()
        if not nxt:
            break
        current = nxt
    return {"chunks": chunks}


def _heap_chunks(argv):
    args = list(argv)
    ctx = {
        "print_arena": _pop_flag(args, "--all", "-a"),
        "allow_unaligned": _pop_flag(args, "--allow-unaligned"),
        "summary": _pop_flag(args, "--summary", "-s"),
        "resolve": _pop_flag(args, "--resolve"),
        "min_size": _safe_int(_pop_value(args, "--min-size", default="0"), 0),
        "max_size": _safe_int(_pop_value(args, "--max-size", default="0"), 0),
        "count": _safe_int(_pop_value(args, "--count", "-n", default="-1"), -1),
    }
    arena_arg = args[0] if args else None

    def should_process(chunk):
        if chunk.size < ctx["min_size"]:
            return False
        if 0 < ctx["max_size"] < chunk.size:
            return False
        return True

    def summary_init():
        return {
            "size_distribution": {},
            "flag_distribution": {
                "PREV_INUSE": {"count": 0, "total_bytes": 0},
                "IS_MMAPPED": {"count": 0, "total_bytes": 0},
                "NON_MAIN_ARENA": {"count": 0, "total_bytes": 0},
            },
        }

    def summary_process(summary, chunk):
        chunk_type = chunk.resolve_type() if ctx["resolve"] else ""
        key = (chunk.size, chunk_type)
        entry = summary["size_distribution"].get(key)
        if not entry:
            entry = {"size": chunk.size, "type": chunk_type, "count": 0, "total_bytes": 0}
            summary["size_distribution"][key] = entry
        entry["count"] += 1
        entry["total_bytes"] += chunk.size
        if chunk.has_p_bit():
            summary["flag_distribution"]["PREV_INUSE"]["count"] += 1
            summary["flag_distribution"]["PREV_INUSE"]["total_bytes"] += chunk.size
        if chunk.has_m_bit():
            summary["flag_distribution"]["IS_MMAPPED"]["count"] += 1
            summary["flag_distribution"]["IS_MMAPPED"]["total_bytes"] += chunk.size
        if chunk.has_n_bit():
            summary["flag_distribution"]["NON_MAIN_ARENA"]["count"] += 1
            summary["flag_distribution"]["NON_MAIN_ARENA"]["total_bytes"] += chunk.size

    def dump_chunks_heap(start, end, arena):
        nb = (
            gef.config["heap-chunks.peek_nb_byte"]
            if "heap-chunks.peek_nb_byte" in gef.config
            else 0
        )
        remaining = ctx["count"]
        summary = summary_init()
        chunks = []
        iterator = GlibcChunk(start, from_base=True, allow_unaligned=ctx["allow_unaligned"])
        for chunk in iterator:
            if chunk.base_address > end:
                raise Exception("Corrupted heap")
            if not should_process(chunk):
                continue
            if remaining == 0:
                break
            if ctx["summary"]:
                summary_process(summary, chunk)
            else:
                entry = _chunk_to_dict(chunk)
                if nb:
                    entry["peek_bytes_hex"] = gef.memory.read(chunk.data_address, nb).hex()
                if chunk.base_address == arena.top:
                    entry["is_top"] = True
                chunks.append(entry)
            remaining -= 1
            if not ctx["summary"] and chunk.base_address == arena.top:
                break
        if ctx["summary"]:
            size_dist = list(summary["size_distribution"].values())
            summary["size_distribution"] = size_dist
            return {"summary": summary}
        return {"chunks": chunks}

    def dump_arena(arena):
        arena_entry = {"arena": _arena_to_dict(arena)}
        heap_addr = arena.heap_addr(allow_unaligned=ctx["allow_unaligned"])
        if heap_addr is None:
            arena_entry["error"] = "No heap section"
            return arena_entry
        if arena.is_main_arena():
            heap_end = arena.top + GlibcChunk(arena.top, from_base=True).size
            arena_entry.update(dump_chunks_heap(heap_addr, heap_end, arena))
        else:
            heaps = []
            heap_infos = arena.get_heap_info_list() or []
            for heap_info in heap_infos:
                entry = {
                    "heap_start": _to_hex(heap_info.heap_start),
                    "heap_end": _to_hex(heap_info.heap_end),
                }
                entry.update(dump_chunks_heap(heap_info.heap_start, heap_info.heap_end, arena))
                heaps.append(entry)
            arena_entry["heaps"] = heaps
        return arena_entry

    arenas = []
    if ctx["print_arena"] or not arena_arg:
        for arena in gef.heap.arenas:
            arenas.append(dump_arena(arena))
            if not ctx["print_arena"]:
                break
    if arena_arg:
        arena_addr = parse_address(arena_arg)
        arena = GlibcArena(f"*{arena_addr:#x}")
        arenas.append(dump_arena(arena))
    return {"arenas": arenas, "summary": ctx["summary"]}


def _walk_bin(arena_addr, index, chunk_cls):
    arena = GlibcArena(arena_addr)
    fd, bk = arena.bin(index)
    if (fd, bk) == (0x00, 0x00):
        return {"index": index, "chunks": [], "empty": True}
    head = chunk_cls(bk, from_base=True).fd
    if fd == head:
        return {"index": index, "chunks": [], "empty": True}
    chunks = []
    seen = set()
    while fd != head:
        if fd in seen:
            return {"index": index, "chunks": chunks, "loop": True}
        seen.add(fd)
        chunk = chunk_cls(fd, from_base=True)
        chunks.append(_chunk_to_dict(chunk))
        fd = chunk.fd
    return {"index": index, "chunks": chunks}


def _heap_bins_tcache(argv):
    if gef.libc.version and gef.libc.version < (2, 26):
        return {"tcache": None, "error": "No tcache in this libc version"}
    current_thread = gdb.selected_thread()
    threads = sorted(gdb.selected_inferior().threads(), key=lambda t: t.num)
    tids = []
    if argv:
        if "all" in argv:
            tids = [t.num for t in threads]
        else:
            tids = [int(x) for x in argv]
    else:
        if current_thread:
            tids = [current_thread.num]
    results = []

    def find_tcache():
        try:
            return parse_address("(void *) tcache")
        except gdb.error:
            heap_base = gef.heap.base_address
            if heap_base is None:
                return 0
            return heap_base + 0x10

    def tcachebin(tcache_base, i):
        TCACHE_MAX_BINS = 0x40
        if i >= TCACHE_MAX_BINS:
            return None, 0
        tcache_chunk = GlibcTcacheChunk(tcache_base)
        new_min = TCACHE_MAX_BINS * 2 + TCACHE_MAX_BINS * gef.arch.ptrsize
        if tcache_chunk.usable_size < new_min:
            tcache_count_size = 1
            count = ord(gef.memory.read(tcache_base + tcache_count_size * i, 1))
        else:
            tcache_count_size = 2
            count = u16(gef.memory.read(tcache_base + tcache_count_size * i, 2))
        chunk = dereference(
            tcache_base + tcache_count_size * TCACHE_MAX_BINS + i * gef.arch.ptrsize
        )
        chunk = GlibcTcacheChunk(int(chunk)) if chunk else None
        return chunk, count

    for thread in threads:
        if thread.num not in tids:
            continue
        thread.switch()
        tcache_addr = find_tcache()
        if tcache_addr == 0:
            results.append({"thread": thread.num, "initialized": False})
            continue
        bins = []
        for i in range(0x40):
            chunk, count = tcachebin(tcache_addr, i)
            chunks = []
            seen = set()
            chunk_size = 0
            while chunk:
                if chunk.data_address in seen:
                    chunks.append({"loop": True, "address": _to_hex(chunk.data_address)})
                    break
                seen.add(chunk.data_address)
                if not chunk_size:
                    chunk_size = chunk.usable_size
                chunks.append(_chunk_to_dict(chunk))
                nxt = chunk.fd
                if nxt == 0:
                    break
                chunk = GlibcTcacheChunk(nxt)
            if chunks:
                tidx = gef.heap.csize2tidx(chunk_size)
                size = gef.heap.tidx2size(tidx)
                bins.append(
                    {
                        "index": i,
                        "tidx": tidx,
                        "size": size,
                        "count": len(seen),
                        "chunks": chunks,
                    }
                )
        results.append({"thread": thread.num, "initialized": True, "bins": bins})

    if current_thread:
        current_thread.switch()
    return {"threads": results}


def _heap_bins_fast(argv):
    SIZE_SZ = gef.arch.ptrsize

    def fastbin_index(sz):
        return (sz >> 4) - 2 if SIZE_SZ == 8 else (sz >> 3) - 2

    MAX_FAST_SIZE = 80 * SIZE_SZ // 4
    nfastbins = fastbin_index(MAX_FAST_SIZE) - 1
    arena = GlibcArena(f"*{parse_address(argv[0]):#x}") if argv else gef.heap.selected_arena
    if arena is None:
        raise Exception("Invalid arena")

    bins = []
    for i in range(nfastbins):
        chunk = arena.fastbin(i)
        chunks = []
        seen = set()
        while True:
            if chunk is None:
                break
            if chunk.data_address in seen:
                chunks.append({"loop": True, "address": _to_hex(chunk.data_address)})
                break
            seen.add(chunk.data_address)
            entry = _chunk_to_dict(chunk)
            entry["incorrect_index"] = fastbin_index(chunk.size) != i
            chunks.append(entry)
            nxt = chunk.fd
            if nxt == 0:
                break
            chunk = GlibcFastChunk(nxt, from_base=True)
        bins.append({"index": i, "size": (i + 2) * SIZE_SZ * 2, "chunks": chunks})
    return {"bins": bins, "arena": _arena_to_dict(arena)}


def _heap_bins_unsorted(argv):
    if not gef.heap.main_arena or not gef.heap.selected_arena:
        raise Exception("Heap not initialized")
    arena_addr = argv[0] if argv else f"{gef.heap.selected_arena.addr:#x}"
    return _walk_bin(f"*{parse_address(arena_addr):#x}", 0, GlibcChunk)


def _heap_bins_small(argv):
    if not gef.heap.main_arena or not gef.heap.selected_arena:
        raise Exception("Heap not initialized")
    arena_addr = argv[0] if argv else f"{gef.heap.selected_arena.address:#x}"
    bins = []
    for i in range(1, 63):
        info = _walk_bin(f"*{parse_address(arena_addr):#x}", i, GlibcChunk)
        if info.get("chunks"):
            bins.append(info)
    return {"bins": bins}


def _heap_bins_large(argv):
    if not gef.heap.main_arena or not gef.heap.selected_arena:
        raise Exception("Heap not initialized")
    arena_addr = argv[0] if argv else f"{gef.heap.selected_arena.addr:#x}"
    bins = []
    for i in range(63, 126):
        info = _walk_bin(f"*{parse_address(arena_addr):#x}", i, GlibcChunk)
        if info.get("chunks"):
            bins.append(info)
    return {"bins": bins}


def _heap_bins(argv):
    if not argv:
        return {
            "tcache": _heap_bins_tcache([]),
            "fast": _heap_bins_fast([]),
            "unsorted": _heap_bins_unsorted([]),
            "small": _heap_bins_small([]),
            "large": _heap_bins_large([]),
        }
    bin_t = argv[0]
    rest = argv[1:]
    if bin_t == "tcache":
        return _heap_bins_tcache(rest)
    if bin_t == "fast":
        return _heap_bins_fast(rest)
    if bin_t == "unsorted":
        return _heap_bins_unsorted(rest)
    if bin_t == "small":
        return _heap_bins_small(rest)
    if bin_t == "large":
        return _heap_bins_large(rest)
    raise Exception("Unknown bin type")


def _heap_cmd(args):
    if not args:
        return {
            "subcommands": ["chunk", "chunks", "bins", "arenas", "set-arena"],
            "selected_arena": _to_hex(gef.heap.selected_arena.addr)
            if gef.heap.selected_arena
            else None,
            "main_arena": _to_hex(gef.heap.main_arena.addr) if gef.heap.main_arena else None,
        }
    sub = args[0]
    rest = args[1:]
    if sub == "set-arena":
        return _heap_set_arena(rest)
    if sub == "arenas":
        return {"arenas": [_arena_to_dict(a) for a in gef.heap.arenas]}
    if sub == "chunk":
        return _heap_chunk(rest)
    if sub == "chunks":
        return _heap_chunks(rest)
    if sub == "bins":
        return _heap_bins(rest)
    raise Exception("Unknown heap subcommand")


def _context_regs():
    ignored = set((gef.config["context.ignore_registers"] or "").split())
    regs = {}
    for reg in gef.arch.all_registers:
        if reg in ignored:
            continue
        reg_expr = _normalize_reg(reg)
        try:
            val = gdb.parse_and_eval(reg_expr)
            regs[reg.lstrip("$")] = _to_hex(val) or str(val)
        except Exception:
            try:
                regs[reg.lstrip("$")] = _to_hex(gef.arch.register(reg_expr))
            except Exception:
                regs[reg.lstrip("$")] = None
    return {"registers": regs, "flags": gef.arch.flag_register_to_human()}


def _context_stack():
    sp = gef.arch.sp
    nb_lines = gef.config["context.nb_lines_stack"]
    show_raw = gef.config["context.show_stack_raw"]
    if show_raw:
        mem = gef.memory.read(sp, 0x10 * nb_lines)
        return {"sp": _to_hex(sp), "raw": True, "lines": _hexdump_bytes(sp, mem)}
    entries = []
    for i in range(nb_lines):
        addr = sp + i * gef.arch.ptrsize
        entries.append({"address": _to_hex(addr), "chain": dereference_from(addr)})
    return {"sp": _to_hex(sp), "raw": False, "entries": entries}


def _context_code():
    nb_insn = gef.config["context.nb_lines_code"]
    nb_insn_prev = gef.config["context.nb_lines_code_prev"]
    pc = gef.arch.pc
    breakpoints = gdb.breakpoints() or []
    if len(breakpoints) and hasattr(breakpoints[-1], "locations"):
        bp_locations = [
            hex(location.address)
            for b in breakpoints
            for location in b.locations
            if location is not None
        ]
    else:
        bp_locations = [
            b.location
            for b in breakpoints
            if b.location and b.location.startswith("*")
        ]
    frame = gdb.selected_frame()
    items = []
    for insn in gef_disassemble(pc, nb_insn, nb_prev=nb_insn_prev):
        entry = {
            "address": _to_hex(insn.address),
            "mnemonic": insn.mnemonic,
            "operands": list(insn.operands),
            "text": str(insn),
            "is_current": insn.address == pc,
            "has_breakpoint": hex(insn.address) in bp_locations,
        }
        if insn.address == pc:
            if gef.arch.is_conditional_branch(insn):
                taken, reason = gef.arch.is_branch_taken(insn)
                entry["branch"] = {
                    "type": "conditional",
                    "taken": bool(taken),
                    "reason": reason,
                    "target": insn.operands[-1].split()[0] if insn.operands else None,
                }
            elif gef.arch.is_call(insn) and gef.config["context.peek_calls"]:
                entry["branch"] = {
                    "type": "call",
                    "target": insn.operands[-1].split()[0] if insn.operands else None,
                }
            elif gef.arch.is_ret(insn) and gef.config["context.peek_ret"]:
                entry["branch"] = {
                    "type": "ret",
                    "target": _to_hex(gef.arch.get_ra(insn, frame)),
                }
        items.append(entry)
    return {"instructions": items}


def _context_args():
    insn = gef_current_instruction(gef.arch.pc)
    if not gef.arch.is_call(insn):
        return {"available": False}
    def size2type(size):
        return {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "QWORD"}.get(size, "")
    if insn.operands and insn.operands[-1].startswith(size2type(gef.arch.ptrsize) + " PTR"):
        target = "*" + insn.operands[-1].split()[-1]
    elif insn.operands and ("$" + insn.operands[0]) in gef.arch.all_registers:
        target = f"*{gef.arch.register('$' + insn.operands[0]):#x}"
    else:
        ops = " ".join(insn.operands)
        if "<" in ops and ">" in ops:
            target = re.sub(r".*<([^\(> ]*).*", r"\1", ops)
        else:
            target = re.sub(r".*(0x[a-fA-F0-9]*).*", r"\1", ops)
    sym = gdb.lookup_global_symbol(target)
    if sym is None:
        return {"mode": "guessed", "function": target, "args": []}
    if sym.type and sym.type.code != gdb.TYPE_CODE_FUNC:
        return {"mode": "error", "function": target, "error": "not a function"}
    args = []
    fields = sym.type.fields() if sym.type else []
    for i, f in enumerate(fields):
        if not f.type:
            continue
        value = gef.arch.get_ith_parameter(i, in_func=False)[1]
        value = "->".join(dereference_from(value))
        name = f.name or f"var_{i}"
        type_name = f.type.name or size2type(f.type.sizeof)
        args.append({"name": name, "type": type_name, "value": value})
    return {"mode": "symbol", "function": target, "args": args}


def _context_memory():
    items = []
    for address, opt in sorted(gef.ui.watches.items()):
        sz, fmt = opt[0:2]
        entry = {"address": _to_hex(address), "size": sz, "format": fmt}
        if fmt == "pointers":
            lines = []
            for i in range(sz):
                addr = address + i * gef.arch.ptrsize
                lines.append({"address": _to_hex(addr), "chain": dereference_from(addr)})
            entry["entries"] = lines
        else:
            entry["data"] = _hexdump_cmd([fmt, _to_hex(address), "--size", str(sz)])
        items.append(entry)
    return {"watches": items}


def _context_source():
    try:
        pc = gef.arch.pc
        symtabline = gdb.find_pc_line(pc)
        symtab = symtabline.symtab
        line_num = symtabline.line - 1
        if not symtab.is_valid():
            return {"available": False}
        fpath = symtab.fullname()
        lines = [cur.rstrip() for cur in open(fpath, "r").read().splitlines()]
    except Exception:
        return {"available": False}

    nb_line = gef.config["context.nb_lines_code"]
    output = []
    for i in range(line_num - nb_line + 1, line_num + nb_line):
        if i < 0 or i >= len(lines):
            continue
        output.append(
            {
                "no": i + 1,
                "text": lines[i],
                "is_current": i == line_num,
            }
        )
    return {
        "file": symtab.filename,
        "line": line_num + 1,
        "lines": output,
    }


def _context_trace():
    nb_backtrace = gef.config["context.nb_lines_backtrace"]
    if nb_backtrace <= 0:
        return {"frames": []}
    frames = []
    current = gdb.newest_frame()
    level = 0
    while current and nb_backtrace > 0:
        if not current.is_valid():
            break
        pc = int(current.pc())
        name = current.name()
        frame = {"level": level, "pc": _to_hex(pc), "name": name}
        frames.append(frame)
        current = current.older()
        level += 1
        nb_backtrace -= 1
    return {"frames": frames}


def _context_threads():
    def reason():
        res = gdb.execute("info program", to_string=True)
        if not res:
            return "NOT RUNNING"
        for line in res.splitlines():
            line = line.strip()
            if line.startswith("It stopped with signal "):
                return line.replace("It stopped with signal ", "").split(",", 1)[0]
            if line == "The program being debugged is not being run.":
                return "NOT RUNNING"
            if line == "It stopped at a breakpoint that has since been deleted.":
                return "TEMPORARY BREAKPOINT"
            if line.startswith("It stopped at breakpoint "):
                return "BREAKPOINT"
            if line == "It stopped after being stepped.":
                return "SINGLE STEP"
        return "STOPPED"

    threads = gdb.selected_inferior().threads()[::-1]
    idx = gef.config["context.nb_lines_threads"]
    if idx > 0:
        threads = threads[0:idx]
    if idx == 0:
        return {"threads": []}
    selected = gdb.selected_thread()
    out = []
    for t in threads:
        entry = {
            "id": t.num,
            "name": t.name,
            "running": t.is_running(),
            "selected": t == selected,
            "reason": reason(),
        }
        out.append(entry)
    return {"threads": out}


def _context_extra():
    return {"messages": [{"level": lvl, "text": txt} for (lvl, txt) in gef.ui.context_messages]}


def _context_cmd(args):
    if args:
        layout = args
    else:
        layout = gef.config["context.layout"].strip().split()
    sections = []
    for section in layout:
        if section.startswith("-"):
            continue
        if section == "legend":
            continue
        if section == "regs":
            sections.append({"name": "regs", "data": _context_regs()})
        elif section == "stack":
            sections.append({"name": "stack", "data": _context_stack()})
        elif section == "code":
            sections.append({"name": "code", "data": _context_code()})
        elif section == "args":
            sections.append({"name": "args", "data": _context_args()})
        elif section == "memory":
            sections.append({"name": "memory", "data": _context_memory()})
        elif section == "source":
            sections.append({"name": "source", "data": _context_source()})
        elif section == "trace":
            sections.append({"name": "trace", "data": _context_trace()})
        elif section == "threads":
            sections.append({"name": "threads", "data": _context_threads()})
        elif section == "extra":
            sections.append({"name": "extra", "data": _context_extra()})
    return {"sections": sections}


def run_json(tool, args):
    try:
        argv = _parse_args(args)
        if tool == "checksec":
            fpath = _get_file()
            if not fpath:
                raise Exception("no file loaded")
            return _ok(tool, args, {"file": fpath, "checksec": Elf(fpath).checksec})
        if tool == "canary":
            res = gef.session.canary
            if not res:
                return _ok(tool, args, {"available": False})
            canary, location = res
            return _ok(tool, args, {"available": True, "address": _to_hex(location), "value": _to_hex(canary)})
        if tool == "aslr":
            ret = gdb.execute("show disable-randomization", to_string=True) or ""
            disabled = ret.strip().endswith("on.")
            return _ok(tool, args, {"aslr": "disabled" if disabled else "enabled", "gdb_disable_randomization": disabled})
        if tool == "vmmap":
            maps = []
            for m in gef.memory.maps:
                maps.append({"start": _to_hex(m.page_start), "end": _to_hex(m.page_end), "offset": m.offset, "perm": str(m.permission), "inode": m.inode, "path": m.path})
            return _ok(tool, args, {"maps": maps})
        if tool == "memory":
            return _ok(tool, args, _memory_cmd(argv))
        if tool == "hexdump":
            return _ok(tool, args, _hexdump_cmd(argv))
        if tool == "xinfo":
            return _ok(tool, args, _xinfo_cmd(argv))
        if tool == "xfiles":
            return _ok(tool, args, _xfiles_cmd(argv))
        if tool == "registers":
            return _ok(tool, args, _registers_cmd(argv))
        if tool == "arch":
            return _ok(tool, args, _arch_cmd())
        if tool == "eval":
            return _ok(tool, args, _eval_cmd(args))
        if tool == "functions":
            return _ok(tool, args, {"functions": sorted(list(gef.gdb.functions.keys()))})
        if tool == "gef_base":
            return _ok(tool, args, {"value": _to_hex(gdb.parse_and_eval("$_base()"))})
        if tool == "gef_stack":
            return _ok(tool, args, {"value": _to_hex(gdb.parse_and_eval("$_stack()"))})
        if tool == "gef_heap":
            return _ok(tool, args, {"value": _to_hex(gdb.parse_and_eval("$_heap()"))})
        if tool == "gef_got":
            return _ok(tool, args, {"value": _to_hex(gdb.parse_and_eval("$_got()"))})
        if tool == "gef_bss":
            return _ok(tool, args, {"value": _to_hex(gdb.parse_and_eval("$_bss()"))})
        if tool == "heap":
            return _ok(tool, args, _heap_cmd(argv))
        if tool == "context":
            return _ok(tool, args, _context_cmd(argv))

        raise Exception(f"unsupported tool: {tool}")
    except Exception as e:
        return _err(tool, args, e)


class GefJsonCommand(gdb.Command):
    """Emit structured JSON using run_json()."""

    def __init__(self):
        super().__init__("gef-json", gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if not argv:
            print(
                json.dumps(
                    _err("gef-json", args, Exception("missing tool")),
                    ensure_ascii=False,
                )
            )
            return
        tool = argv[0]
        rest = argv[1:]
        print(json.dumps(run_json(tool, rest), ensure_ascii=False))


GefJsonCommand()
