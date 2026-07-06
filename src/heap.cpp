#include "heap.hpp"

#include "config.hpp"

#include <algorithm>
#include <optional>
#include <vector>

namespace wef {

namespace {

struct HeapSummary {
    ULONG index = 0;
    ULONG64 address = 0;
    ULONG flags = 0;
    ULONG forceFlags = 0;
    UCHAR frontEndType = 0;
    bool gotFlags = false;
    bool gotForceFlags = false;
    bool gotFrontEnd = false;
    MEMORY_BASIC_INFORMATION64 region = {};
    bool gotRegion = false;
};

struct HeapChunk {
    ULONG64 heap = 0;
    ULONG64 segment = 0;
    ULONG64 address = 0;
    ULONG64 userAddress = 0;
    ULONG64 size = 0;
    ULONG64 usableSize = 0;
    USHORT sizeUnits = 0;
    USHORT flags = 0;
    USHORT previousSize = 0;
};

struct HeapSegment {
    ULONG64 heap = 0;
    ULONG64 address = 0;
    ULONG64 firstEntry = 0;
    ULONG64 lastValidEntry = 0;
    MEMORY_BASIC_INFORMATION64 region = {};
    bool gotRegion = false;
};

template <typename T>
bool readValue(DbgSession& session, ULONG64 address, T& value) {
    ULONG bytesRead = 0;
    const HRESULT hr = session.readVirtual(address, &value, sizeof(T), &bytesRead);
    return SUCCEEDED(hr) && bytesRead == sizeof(T);
}

bool fieldOffset(DbgSession& session, PCSTR type, PCSTR field, ULONG& offset) {
    const std::string qualified(type);
    const size_t bang = qualified.find('!');
    if (bang == std::string::npos || bang == 0 || bang + 1 >= qualified.size()) {
        return false;
    }

    const std::string moduleName = qualified.substr(0, bang);
    const std::string typeName = qualified.substr(bang + 1);

    ULONG64 moduleBase = 0;
    if (FAILED(session.symbols()->GetModuleByModuleName(moduleName.c_str(), 0, nullptr, &moduleBase))) {
        return false;
    }

    ULONG typeId = 0;
    if (FAILED(session.symbols()->GetTypeId(moduleBase, typeName.c_str(), &typeId))) {
        return false;
    }

    return SUCCEEDED(session.symbols()->GetFieldOffset(moduleBase, typeId, field, &offset));
}

bool readFieldUlong(DbgSession& session, ULONG64 base, PCSTR type, PCSTR field, ULONG& value) {
    ULONG offset = 0;
    if (!fieldOffset(session, type, field, offset)) {
        return false;
    }
    return readValue(session, base + offset, value);
}

bool readFieldUchar(DbgSession& session, ULONG64 base, PCSTR type, PCSTR field, UCHAR& value) {
    ULONG offset = 0;
    if (!fieldOffset(session, type, field, offset)) {
        return false;
    }
    return readValue(session, base + offset, value);
}

bool readFieldUshort(DbgSession& session, ULONG64 base, PCSTR type, PCSTR field, USHORT& value) {
    ULONG offset = 0;
    if (!fieldOffset(session, type, field, offset)) {
        return false;
    }
    return readValue(session, base + offset, value);
}

bool readFieldPointer(DbgSession& session, ULONG64 base, PCSTR type, PCSTR field, ULONG64& value) {
    ULONG offset = 0;
    if (!fieldOffset(session, type, field, offset)) {
        return false;
    }
    return session.readPointer(base + offset, value);
}

ULONG64 heapEntryUnit(const DbgSession& session) {
    return session.pointerSize() == 8 ? 16 : 8;
}

bool rangeContains(ULONG64 base, ULONG64 size, ULONG64 address) {
    if (size == 0 || address < base) {
        return false;
    }
    return address - base < size;
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::string text;
    for (const unsigned char byte : bytes) {
        if (!text.empty()) {
            text += ' ';
        }
        text += formatHex(byte, 2);
    }
    return text;
}

std::string bytesToAscii(const std::vector<unsigned char>& bytes) {
    std::string text;
    text.reserve(bytes.size());
    for (const unsigned char byte : bytes) {
        text.push_back(byte >= 0x20 && byte <= 0x7e ? static_cast<char>(byte) : '.');
    }
    return text;
}

bool readBytes(DbgSession& session, ULONG64 address, ULONG64 size, std::vector<unsigned char>& bytes) {
    if (size == 0 || size > 0xffffffffULL) {
        return false;
    }

    bytes.assign(static_cast<size_t>(size), 0);
    ULONG bytesRead = 0;
    const HRESULT hr = session.readVirtual(address, bytes.data(), static_cast<ULONG>(bytes.size()), &bytesRead);
    if (FAILED(hr) || bytesRead == 0) {
        bytes.clear();
        return false;
    }
    bytes.resize(bytesRead);
    return true;
}

std::string padRight(std::string text, size_t width) {
    if (text.size() >= width) {
        return text;
    }
    text.append(width - text.size(), ' ');
    return text;
}

std::string dmlColor(std::string_view text, std::string_view color) {
    return "<col fg=\"" + std::string(color) + "\">" + dmlEscape(text) + "</col>";
}

bool readPebHeapList(DbgSession& session, ULONG64& heapsAddress, ULONG& heapCount) {
    ULONG64 peb = 0;
    if (!session.evaluate("@$peb", peb) || peb == 0) {
        return false;
    }

    ULONG countOffset = 0;
    ULONG heapsOffset = 0;
    if (!fieldOffset(session, "ntdll!_PEB", "NumberOfHeaps", countOffset) ||
        !fieldOffset(session, "ntdll!_PEB", "ProcessHeaps", heapsOffset)) {
        return false;
    }

    if (!readValue(session, peb + countOffset, heapCount)) {
        return false;
    }
    return session.readPointer(peb + heapsOffset, heapsAddress);
}

std::string chunkFlags(USHORT flags) {
    std::string text;
    if ((flags & 0x01) != 0) {
        text += "busy";
    } else {
        text += "free";
    }
    if ((flags & 0x02) != 0) {
        text += "|extra";
    }
    if ((flags & 0x04) != 0) {
        text += "|fill";
    }
    if ((flags & 0x08) != 0) {
        text += "|virtual";
    }
    if ((flags & 0x10) != 0) {
        text += "|last";
    }
    return text;
}

struct ChunkStats {
    ULONG64 busyCount = 0;
    ULONG64 freeCount = 0;
    ULONG64 virtualCount = 0;
    ULONG64 busyBytes = 0;
    ULONG64 freeBytes = 0;
};

ChunkStats summarizeChunks(const std::vector<HeapChunk>& chunks) {
    ChunkStats stats;
    for (const auto& chunk : chunks) {
        const bool busy = (chunk.flags & 0x01) != 0;
        const bool virt = (chunk.flags & 0x08) != 0;
        if (busy) {
            ++stats.busyCount;
            stats.busyBytes += chunk.size;
        } else {
            ++stats.freeCount;
            stats.freeBytes += chunk.size;
        }
        if (virt) {
            ++stats.virtualCount;
        }
    }
    return stats;
}

std::string heapFlags(ULONG flags) {
    struct FlagName {
        ULONG bit;
        const char* name;
    };

    constexpr FlagName names[] = {
        {0x00000001, "NO_SERIALIZE"},
        {0x00000002, "GROWABLE"},
        {0x00000004, "GENERATE_EXCEPTIONS"},
        {0x00000008, "ZERO_MEMORY"},
        {0x00000010, "REALLOC_IN_PLACE_ONLY"},
        {0x00000020, "TAIL_CHECK"},
        {0x00000040, "FREE_CHECK"},
        {0x00000080, "DISABLE_COALESCE"},
        {0x00008000, "PSEUDO_TAG"},
        {0x00010000, "ALIGN_16"},
        {0x00020000, "ENABLE_TRACING"},
        {0x00040000, "ENABLE_EXECUTE"},
        {0x10000000, "SKIP_VALIDATION"},
        {0x20000000, "VALIDATE_ALL"},
        {0x40000000, "VALIDATE_PARAMS"},
    };

    std::string text;
    ULONG known = 0;
    for (const auto& item : names) {
        if ((flags & item.bit) != 0) {
            if (!text.empty()) {
                text += "|";
            }
            text += item.name;
            known |= item.bit;
        }
    }

    const ULONG unknown = flags & ~known;
    if (unknown != 0) {
        if (!text.empty()) {
            text += "|";
        }
        text += "0x" + formatHex(unknown, 8);
    }

    return text.empty() ? "none" : text;
}

std::string heapKind(UCHAR frontEndType) {
    switch (frontEndType) {
    case 0:
        return "backend";
    case 1:
        return "lookaside";
    case 2:
        return "lfh";
    default:
        return "type-" + formatHex(frontEndType);
    }
}

std::vector<HeapSegment> collectHeapSegments(DbgSession& session, const Output& out, ULONG64 heapAddress, ULONG64 maxSegments, bool quiet = false) {
    std::vector<HeapSegment> segments;
    ULONG segmentListOffset = 0;
    ULONG segmentEntryOffset = 0;
    if (!fieldOffset(session, "ntdll!_HEAP", "SegmentList", segmentListOffset) ||
        !fieldOffset(session, "ntdll!_HEAP_SEGMENT", "SegmentListEntry", segmentEntryOffset)) {
        if (!quiet) {
            out.warning("heap segment inspection needs ntdll _HEAP and _HEAP_SEGMENT symbols\n");
        }
        return segments;
    }

    const ULONG64 listHead = heapAddress + segmentListOffset;
    ULONG64 currentLink = 0;
    if (!session.readPointer(listHead, currentLink)) {
        if (!quiet) {
            out.warning("could not read heap SegmentList\n");
        }
        return segments;
    }

    ULONG64 segmentCount = 0;
    while (currentLink != 0 && currentLink != listHead && segmentCount < maxSegments) {
        const ULONG64 segment = currentLink - segmentEntryOffset;
        ULONG64 nextLink = 0;
        if (!session.readPointer(currentLink, nextLink)) {
            if (!quiet) {
                out.warning("stopped segment walk after unreadable LIST_ENTRY\n");
            }
            break;
        }

        ULONG64 firstEntry = 0;
        ULONG64 lastValidEntry = 0;
        if (readFieldPointer(session, segment, "ntdll!_HEAP_SEGMENT", "FirstEntry", firstEntry) &&
            readFieldPointer(session, segment, "ntdll!_HEAP_SEGMENT", "LastValidEntry", lastValidEntry)) {
            HeapSegment item;
            item.heap = heapAddress;
            item.address = segment;
            item.firstEntry = firstEntry;
            item.lastValidEntry = lastValidEntry;
            item.gotRegion = session.queryVirtual(segment, item.region);
            segments.push_back(item);
        }

        currentLink = nextLink;
        ++segmentCount;
    }

    return segments;
}

std::vector<HeapChunk> collectHeapChunks(DbgSession& session, const Output& out, ULONG64 heapAddress, ULONG64 maxSegments, ULONG64 maxChunks, bool quiet = false) {
    std::vector<HeapChunk> chunks;
    const auto segments = collectHeapSegments(session, out, heapAddress, maxSegments, quiet);
    const ULONG64 entryUnit = heapEntryUnit(session);
    for (const auto& segment : segments) {
        ULONG64 entry = segment.firstEntry;
        ULONG64 chunkCount = 0;
        while (entry != 0 && entry < segment.lastValidEntry && chunks.size() < maxChunks && chunkCount < maxChunks) {
            USHORT sizeUnits = 0;
            USHORT flags = 0;
            USHORT previousSize = 0;
            if (!readFieldUshort(session, entry, "ntdll!_HEAP_ENTRY", "Size", sizeUnits) ||
                !readFieldUshort(session, entry, "ntdll!_HEAP_ENTRY", "PreviousSize", previousSize)) {
                break;
            }
            readFieldUshort(session, entry, "ntdll!_HEAP_ENTRY", "Flags", flags);
            if (sizeUnits == 0) {
                break;
            }

            const ULONG64 chunkSize = static_cast<ULONG64>(sizeUnits) * entryUnit;
            if (chunkSize < entryUnit) {
                break;
            }

            HeapChunk chunk;
            chunk.heap = heapAddress;
            chunk.segment = segment.address;
            chunk.address = entry;
            chunk.userAddress = entry + entryUnit;
            chunk.size = chunkSize;
            chunk.usableSize = chunkSize - entryUnit;
            chunk.sizeUnits = sizeUnits;
            chunk.flags = flags;
            chunk.previousSize = previousSize;
            chunks.push_back(chunk);
            entry += chunkSize;
            ++chunkCount;
        }
    }

    return chunks;
}

std::optional<HeapChunk> findContainingChunk(DbgSession& session, const Output& out, const std::vector<HeapSummary>& heaps, ULONG64 address) {
    const ULONG64 maxSegments = configGetNumber("heap.vis.max_segments", 16);
    const ULONG64 maxChunks = configGetNumber("heap.chunk.max_search_chunks", 4096);
    for (const auto& heap : heaps) {
        const auto chunks = collectHeapChunks(session, out, heap.address, maxSegments, maxChunks, true);
        for (const auto& chunk : chunks) {
            if (rangeContains(chunk.address, chunk.size, address) || address == chunk.userAddress) {
                return chunk;
            }
        }
    }
    return std::nullopt;
}

void printChunkRow(const Output& out, ULONG index, const HeapChunk& chunk) {
    const std::string indexText = formatHex(index, 2);
    const std::string headerText = formatAddress(chunk.address);
    const std::string userText = formatAddress(chunk.userAddress);
    const std::string sizeText = "0x" + formatHex(chunk.size, 8);
    const std::string usableText = "0x" + formatHex(chunk.usableSize, 8);
    const std::string flagsText = chunkFlags(chunk.flags);
    std::string line = "  ";
    line += indexText;
    line += "   ";
    line += headerText;
    line += "  ";
    line += userText;
    line += "  ";
    line += sizeText;
    line += "  ";
    line += usableText;
    line += "  ";
    line += flagsText;

    const std::string color = (chunk.flags & 0x08) != 0 ? "magenta" : ((chunk.flags & 0x01) != 0 ? "green" : "yellow");
    const std::string dml =
        "  " + dmlColor(padRight(indexText, 4), "gray") +
        dmlColor(headerText, "white") + "  " +
        dmlColor(userText, "cyan") + "  " +
        dmlColor(sizeText, "white") + "  " +
        dmlColor(usableText, "white") + "  " +
        dmlColor(flagsText, color);
    out.dmlLine(line, dml);
}

std::string chunkState(const HeapChunk& chunk) {
    if ((chunk.flags & 0x08) != 0) {
        return "virtual";
    }
    return (chunk.flags & 0x01) != 0 ? "allocated" : "free";
}

std::string chunkStateColor(const HeapChunk& chunk) {
    if ((chunk.flags & 0x08) != 0) {
        return "magenta";
    }
    return (chunk.flags & 0x01) != 0 ? "green" : "yellow";
}

void printGefStyleChunk(DbgSession& session, const Output& out, ULONG64 index, const HeapChunk& chunk, ULONG64 peekBytes) {
    const std::string indexText = formatHex(index, 2);
    const std::string headerText = formatAddress(chunk.address);
    const std::string userText = formatAddress(chunk.userAddress);
    const std::string nextText = formatAddress(chunk.address + chunk.size);
    const std::string sizeText = "0x" + formatHex(chunk.size);
    const std::string usableText = "0x" + formatHex(chunk.usableSize);
    const ULONG64 entryUnit = chunk.sizeUnits == 0 ? 0 : chunk.size / chunk.sizeUnits;
    const std::string prevText = "0x" + formatHex(static_cast<ULONG64>(chunk.previousSize) * entryUnit);
    const std::string flagsText = chunkFlags(chunk.flags);
    const std::string stateText = chunkState(chunk);
    const std::string color = chunkStateColor(chunk);

    const std::string plain =
        "  " + indexText + "  Chunk(addr=" + headerText +
        ", user=" + userText +
        ", size=" + sizeText +
        ", flags=" + flagsText + ")";
    const std::string dml =
        "  " + dmlColor(indexText, "gray") + "  " +
        dmlColor("Chunk", color) +
        "(addr=" + dmlColor(headerText, "white") +
        ", user=" + dmlColor(userText, "cyan") +
        ", size=" + dmlColor(sizeText, "white") +
        ", flags=" + dmlColor(flagsText, color) + ")";
    out.dmlLine(plain, dml);

    out.dmlLine(
        "      [" + stateText + "] prev=" + prevText + " usable=" + usableText + " next=" + nextText,
        "      " + dmlColor("[" + stateText + "]", color) +
            " prev=" + dmlColor(prevText, "white") +
            " usable=" + dmlColor(usableText, "white") +
            " next=" + dmlColor(nextText, "white"));

    if (peekBytes == 0 || chunk.usableSize == 0) {
        return;
    }

    std::vector<unsigned char> bytes;
    const ULONG64 readSize = std::min<ULONG64>(chunk.usableSize, peekBytes);
    if (!readBytes(session, chunk.userAddress, readSize, bytes) || bytes.empty()) {
        out.dmlLine(
            "      contents <unreadable>",
            "      " + dmlColor("contents", "gray") + " " + dmlColor("<unreadable>", "red"));
        return;
    }

    const std::string hex = bytesToHex(bytes);
    const std::string ascii = bytesToAscii(bytes);
    out.dmlLine(
        "      contents " + hex + "  |" + ascii + "|",
        "      " + dmlColor("contents", "gray") + " " +
            dmlColor(hex, "white") + "  " +
            dmlColor("|" + ascii + "|", "cyan"));
}

void printGefStyleHeapLayout(DbgSession& session, const Output& out, const std::vector<HeapChunk>& chunks, ULONG64 peekBytes) {
    ULONG64 currentSegment = 0;
    ULONG64 index = 0;
    for (const auto& chunk : chunks) {
        if (chunk.segment != currentSegment) {
            currentSegment = chunk.segment;
            out.dmlLine(
                "  segment " + formatAddress(currentSegment),
                "  " + dmlColor("segment", "gray") + " " + dmlColor(formatAddress(currentSegment), "cyan"));
        }
        printGefStyleChunk(session, out, index, chunk, peekBytes);
        ++index;
    }
}

void printDetailedChunk(const Output& out, const HeapChunk& chunk, ULONG64 requested) {
    out.heading("Heap Chunk");
    out.field("requested", formatAddress(requested));
    out.field("heap", formatAddress(chunk.heap));
    out.field("segment", formatAddress(chunk.segment));
    out.field("header", formatAddress(chunk.address));
    out.field("user", formatAddress(chunk.userAddress));
    out.field("size", "0x" + formatHex(chunk.size));
    out.field("usable", "0x" + formatHex(chunk.usableSize));
    out.field("units", "0x" + formatHex(chunk.sizeUnits));
    out.field("previous units", "0x" + formatHex(chunk.previousSize));
    out.field("previous bytes", "0x" + formatHex(static_cast<ULONG64>(chunk.previousSize) * (chunk.size / chunk.sizeUnits)));
    out.field("next", formatAddress(chunk.address + chunk.size));
    out.field("flags", chunkFlags(chunk.flags) + " (0x" + formatHex(chunk.flags, 2) + ")");
    out.dmlLine(
        "  actions: [hexdump user] [telescope user] [heap chunks] [validate heap]",
        "  " + dmlColor("actions", "gray") + ": " +
            dmlCommandLink("hexdump user", "!wef.hexdump " + formatAddress(chunk.userAddress) + " L80") + " " +
            dmlCommandLink("telescope user", "!wef.telescope " + formatAddress(chunk.userAddress) + " L8") + " " +
            dmlCommandLink("heap chunks", "!wef.heaps chunks " + formatAddress(chunk.heap)) + " " +
            dmlCommandLink("validate heap", "!wef.heaps validate " + formatAddress(chunk.heap)));
}

void printSegmentRows(DbgSession& session, const Output& out, const std::vector<HeapSummary>& heaps, ULONG64 maxSegments) {
    out.heading("Heap Segments");
    out.line("  heap               segment            first              last               size        region");
    out.line("  -----------------  -----------------  -----------------  -----------------  ----------  ------------------------------");
    for (const auto& heap : heaps) {
        const auto segments = collectHeapSegments(session, out, heap.address, maxSegments);
        for (const auto& segment : segments) {
            std::string line = "  ";
            line += formatAddress(heap.address);
            line += "  ";
            line += formatAddress(segment.address);
            line += "  ";
            line += formatAddress(segment.firstEntry);
            line += "  ";
            line += formatAddress(segment.lastValidEntry);
            line += "  0x";
            line += formatHex(segment.lastValidEntry > segment.firstEntry ? segment.lastValidEntry - segment.firstEntry : 0, 8);
            line += "  ";
            if (segment.gotRegion) {
                line += stateToString(segment.region.State) + " " + protectionToString(segment.region.Protect) + " " + typeToString(segment.region.Type);
            } else {
                line += "unknown";
            }
            out.line(line);
        }
    }
}

void printHeapFlagRows(const Output& out, const std::vector<HeapSummary>& heaps) {
    out.heading("Heap Flags");
    for (const auto& heap : heaps) {
        out.line("  Heap [" + formatHex(heap.index, 2) + "] " + formatAddress(heap.address));
        if (heap.gotFlags) {
            out.line("    Flags:      0x" + formatHex(heap.flags, 8) + " " + heapFlags(heap.flags));
        } else {
            out.line("    Flags:      unavailable");
        }
        if (heap.gotForceFlags) {
            out.line("    ForceFlags: 0x" + formatHex(heap.forceFlags, 8) + " " + heapFlags(heap.forceFlags));
        } else {
            out.line("    ForceFlags: unavailable");
        }
        if (heap.gotFrontEnd) {
            out.line("    Front-end:  " + heapKind(heap.frontEndType));
        }
    }
}

HeapSummary inspectHeap(DbgSession& session, ULONG index, ULONG64 heapAddress) {
    HeapSummary heap;
    heap.index = index;
    heap.address = heapAddress;
    heap.gotFlags = readFieldUlong(session, heapAddress, "ntdll!_HEAP", "Flags", heap.flags);
    heap.gotForceFlags = readFieldUlong(session, heapAddress, "ntdll!_HEAP", "ForceFlags", heap.forceFlags);
    heap.gotFrontEnd = readFieldUchar(session, heapAddress, "ntdll!_HEAP", "FrontEndHeapType", heap.frontEndType);
    heap.gotRegion = session.queryVirtual(heapAddress, heap.region);
    return heap;
}

void printHeapRow(const Output& out, const HeapSummary& heap) {
    std::string line = "  ";
    line += formatHex(heap.index, 2);
    line += "   ";
    line += formatAddress(heap.address);
    line += "  ";
    line += heap.gotFlags ? "0x" + formatHex(heap.flags, 8) : "unavail   ";
    line += "  ";
    line += heap.gotForceFlags ? "0x" + formatHex(heap.forceFlags, 8) : "unavail   ";
    line += "  ";
    line += heap.gotFrontEnd ? heapKind(heap.frontEndType) : "unavail";
    line += "  ";
    if (heap.gotRegion) {
        line += stateToString(heap.region.State) + " " + protectionToString(heap.region.Protect) + " " + typeToString(heap.region.Type);
    } else {
        line += "unknown";
    }
    out.line(line);
}

std::vector<HeapSummary> collectHeaps(DbgSession& session, const Output& out, ULONG64 limit, ULONG64 singleHeap) {
    std::vector<HeapSummary> heaps;
    if (singleHeap != 0) {
        heaps.push_back(inspectHeap(session, 0, singleHeap));
        return heaps;
    }

    ULONG64 heapsAddress = 0;
    ULONG heapCount = 0;
    if (!readPebHeapList(session, heapsAddress, heapCount)) {
        out.error("could not read PEB heap list; ntdll symbols may be unavailable\n");
        return heaps;
    }

    if (heapCount == 0 || heapsAddress == 0) {
        out.warning("PEB reports no process heaps\n");
        return heaps;
    }

    const ULONG count = static_cast<ULONG>(heapCount > limit ? limit : heapCount);
    heaps.reserve(count);
    for (ULONG i = 0; i < count; ++i) {
        ULONG64 heapAddress = 0;
        if (!session.readPointer(heapsAddress + (i * session.pointerSize()), heapAddress)) {
            out.line("  " + formatHex(i, 2) + "   <read failed>");
            continue;
        }
        heaps.push_back(inspectHeap(session, i, heapAddress));
    }

    if (heapCount > limit) {
        out.warning("heap output truncated; use !wef.heaps L<count> to show more\n");
    }
    return heaps;
}

bool parseHeapArgs(DbgSession& session, const Output& out, const std::vector<std::string>& args, ULONG64& singleHeap, ULONG64& limit) {
    singleHeap = 0;
    limit = configGetNumber("heap.max_count", 80);
    for (const auto& arg : args) {
        ULONG64 parsed = 0;
        if (parseLengthToken(arg, parsed)) {
            limit = parsed;
            continue;
        }
        if (singleHeap != 0 || (!session.evaluate(arg, parsed) && !parseNumber(arg, parsed))) {
            out.line("usage:");
            out.line("  !wef.heaps");
            out.line("  !wef.heaps L<count>");
            out.line("  !wef.heaps <heap-address>");
            out.line("  alias after !wef.install: wef-heap [L<count>|heap-address]");
            out.line("  !vis [L<count>|heap-address]");
            return false;
        }
        singleHeap = parsed;
    }
    return true;
}

bool evalAddress(DbgSession& session, const std::string& text, ULONG64& value) {
    return session.evaluate(text, value) || parseNumber(text, value);
}

bool parseHeapSelection(DbgSession& session, const Output& out, const std::vector<std::string>& args, size_t start, ULONG64& singleHeap, ULONG64& limit) {
    std::vector<std::string> rest;
    for (size_t i = start; i < args.size(); ++i) {
        rest.push_back(args[i]);
    }
    return parseHeapArgs(session, out, rest, singleHeap, limit);
}

std::vector<unsigned char> numberPattern(ULONG64 value, ULONG pointerSize) {
    std::vector<unsigned char> bytes(pointerSize, 0);
    for (ULONG i = 0; i < pointerSize; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

std::vector<unsigned char> textPattern(const std::string& text) {
    return std::vector<unsigned char>(text.begin(), text.end());
}

std::vector<HeapSummary> selectedHeaps(DbgSession& session, const Output& out, const std::vector<std::string>& args, size_t start) {
    ULONG64 singleHeap = 0;
    ULONG64 limit = 0;
    if (!parseHeapSelection(session, out, args, start, singleHeap, limit)) {
        return {};
    }
    return collectHeaps(session, out, limit, singleHeap);
}

void usage(const Output& out) {
    out.line("usage:");
    out.line("  !wef.heaps [L<count>|heap-address]");
    out.line("  !wef.heaps flags [L<count>|heap-address]");
    out.line("  !wef.heaps segments [L<count>|heap-address]");
    out.line("  !wef.heaps chunks [-busy|-free] [-contains <addr>] [L<count>|heap-address]");
    out.line("  !wef.heaps chunk <addr>");
    out.line("  !wef.heaps find <addr|text> [L<count>|heap-address]");
    out.line("  !wef.heaps validate [L<count>|heap-address]");
    out.line("  alias after !wef.install: wef-heap [L<count>|heap-address]");
}

HRESULT runHeapFlags(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const auto heaps = selectedHeaps(session, out, args, 1);
    printHeapFlagRows(out, heaps);
    return S_OK;
}

HRESULT runHeapSegments(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const auto heaps = selectedHeaps(session, out, args, 1);
    printSegmentRows(session, out, heaps, configGetNumber("heap.vis.max_segments", 16));
    return S_OK;
}

HRESULT runHeapChunks(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    bool onlyBusy = false;
    bool onlyFree = false;
    ULONG64 contains = 0;
    bool hasContains = false;
    std::vector<std::string> heapArgs;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "-busy") {
            onlyBusy = true;
            continue;
        }
        if (args[i] == "-free") {
            onlyFree = true;
            continue;
        }
        if (args[i] == "-contains") {
            if (i + 1 >= args.size() || !evalAddress(session, args[i + 1], contains)) {
                out.line("usage: !wef.heaps chunks [-busy|-free] [-contains <addr>] [L<count>|heap-address]");
                return S_OK;
            }
            hasContains = true;
            ++i;
            continue;
        }
        heapArgs.push_back(args[i]);
    }

    ULONG64 singleHeap = 0;
    ULONG64 limit = 0;
    if (!parseHeapArgs(session, out, heapArgs, singleHeap, limit)) {
        return S_OK;
    }

    const auto heaps = collectHeaps(session, out, limit, singleHeap);
    out.heading("Heap Chunks");
    out.line("  #    header             user               size        usable      flags");
    out.line("  --   -----------------  -----------------  ----------  ----------  ------------------------------");
    for (const auto& heap : heaps) {
        const auto chunks = collectHeapChunks(
            session,
            out,
            heap.address,
            configGetNumber("heap.vis.max_segments", 16),
            configGetNumber("heap.vis.max_chunks", 160));
        ULONG shown = 0;
        for (const auto& chunk : chunks) {
            const bool busy = (chunk.flags & 0x01) != 0;
            if ((onlyBusy && !busy) || (onlyFree && busy)) {
                continue;
            }
            if (hasContains && !rangeContains(chunk.address, chunk.size, contains)) {
                continue;
            }
            printChunkRow(out, shown, chunk);
            ++shown;
        }
    }
    return S_OK;
}

HRESULT runHeapChunk(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        out.line("usage: !wef.heaps chunk <addr>");
        return S_OK;
    }

    ULONG64 address = 0;
    if (!evalAddress(session, args[1], address)) {
        out.error("could not evaluate address: " + args[1] + "\n");
        return S_OK;
    }

    const auto heaps = collectHeaps(session, out, configGetNumber("heap.max_count", 80), 0);
    const auto found = findContainingChunk(session, out, heaps, address);
    if (!found) {
        out.error("no backend heap chunk contains " + formatAddress(address) + "\n");
        return S_OK;
    }

    printDetailedChunk(out, *found, address);
    std::vector<unsigned char> preview;
    if (readBytes(session, found->userAddress, std::min<ULONG64>(found->usableSize, 32), preview)) {
        out.field("user bytes", bytesToHex(preview));
    }
    return S_OK;
}

HRESULT runHeapFind(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        out.line("usage: !wef.heaps find <addr|text> [L<count>|heap-address]");
        return S_OK;
    }

    ULONG64 numeric = 0;
    const bool numericPattern = evalAddress(session, args[1], numeric);
    const std::vector<unsigned char> pattern = numericPattern ? numberPattern(numeric, session.pointerSize()) : textPattern(args[1]);
    if (pattern.empty()) {
        out.error("empty heap search pattern\n");
        return S_OK;
    }

    const auto heaps = selectedHeaps(session, out, args, 2);
    out.heading("Heap Search");
    out.line("  pattern: " + bytesToHex(pattern));
    out.line("  heap               chunk              hit                flags");
    out.line("  -----------------  -----------------  -----------------  ------------------------------");

    ULONG64 shown = 0;
    const ULONG64 maxHits = configGetNumber("heap.find.max_hits", 80);
    for (const auto& heap : heaps) {
        const auto chunks = collectHeapChunks(
            session,
            out,
            heap.address,
            configGetNumber("heap.vis.max_segments", 16),
            configGetNumber("heap.chunk.max_search_chunks", 4096),
            true);
        for (const auto& chunk : chunks) {
            if (shown >= maxHits) {
                out.warning("heap search truncated; raise heap.find.max_hits to show more hits\n");
                return S_OK;
            }
            std::vector<unsigned char> bytes;
            if (!readBytes(session, chunk.userAddress, std::min<ULONG64>(chunk.usableSize, configGetNumber("heap.find.max_chunk_read", 0x10000)), bytes)) {
                continue;
            }
            const auto found = std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end());
            if (found == bytes.end()) {
                continue;
            }

            const ULONG64 hit = chunk.userAddress + static_cast<ULONG64>(found - bytes.begin());
            out.line("  " + formatAddress(heap.address) + "  " + formatAddress(chunk.address) + "  " + formatAddress(hit) + "  " + chunkFlags(chunk.flags));
            ++shown;
        }
    }

    if (shown == 0) {
        out.warning("no heap matches found\n");
    }
    return S_OK;
}

HRESULT runHeapValidate(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const auto heaps = selectedHeaps(session, out, args, 1);
    out.heading("Heap Validation");
    ULONG64 issueCount = 0;
    for (const auto& heap : heaps) {
        ULONG64 previousEnd = 0;
        const auto chunks = collectHeapChunks(
            session,
            out,
            heap.address,
            configGetNumber("heap.vis.max_segments", 16),
            configGetNumber("heap.chunk.max_search_chunks", 4096));
        for (const auto& chunk : chunks) {
            if (chunk.size == 0 || (chunk.size % heapEntryUnit(session)) != 0) {
                out.error("bad size at " + formatAddress(chunk.address) + "\n");
                ++issueCount;
            }
            if (previousEnd != 0 && chunk.address < previousEnd) {
                out.error("overlapping chunk at " + formatAddress(chunk.address) + "\n");
                ++issueCount;
            }
            previousEnd = chunk.address + chunk.size;
        }
        out.line("  " + formatAddress(heap.address) + ": checked " + formatHex(static_cast<ULONG64>(chunks.size())) + " chunks");
    }
    if (issueCount == 0) {
        out.line("  no structural issues found in walked backend chunks");
    }
    return S_OK;
}

}

HRESULT runHeap(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const TargetInfo target = session.targetInfo();
    if (!target.userMode) {
        out.error("heap requires a user-mode target\n");
        return S_OK;
    }

    if (!args.empty()) {
        if (args[0] == "help" || args[0] == "-h" || args[0] == "/?") {
            usage(out);
            return S_OK;
        }
        if (args[0] == "flags") {
            return runHeapFlags(session, out, args);
        }
        if (args[0] == "segments") {
            return runHeapSegments(session, out, args);
        }
        if (args[0] == "chunks") {
            return runHeapChunks(session, out, args);
        }
        if (args[0] == "chunk") {
            return runHeapChunk(session, out, args);
        }
        if (args[0] == "find") {
            return runHeapFind(session, out, args);
        }
        if (args[0] == "validate") {
            return runHeapValidate(session, out, args);
        }
        if (args[0] == "list") {
            std::vector<std::string> listArgs(args.begin() + 1, args.end());
            ULONG64 singleHeap = 0;
            ULONG64 limit = 0;
            if (!parseHeapArgs(session, out, listArgs, singleHeap, limit)) {
                return S_OK;
            }

            out.heading("Windows Heaps");
            out.line("  #    heap               flags       force      frontend  region");
            out.line("  --   -----------------  ----------  ----------  --------  ------------------------------");
            const auto heaps = collectHeaps(session, out, limit, singleHeap);
            for (const auto& heap : heaps) {
                printHeapRow(out, heap);
            }
            return S_OK;
        }
    }

    ULONG64 singleHeap = 0;
    ULONG64 limit = 0;
    if (!parseHeapArgs(session, out, args, singleHeap, limit)) {
        return S_OK;
    }

    out.heading("Windows Heaps");
    out.line("  #    heap               flags       force      frontend  region");
    out.line("  --   -----------------  ----------  ----------  --------  ------------------------------");

    const auto heaps = collectHeaps(session, out, limit, singleHeap);
    for (const auto& heap : heaps) {
        printHeapRow(out, heap);
    }
    return S_OK;
}

HRESULT runHeapVis(DbgSession& session, const Output& out, const std::vector<std::string>& args) {
    const TargetInfo target = session.targetInfo();
    if (!target.userMode) {
        out.error("vis requires a user-mode target\n");
        return S_OK;
    }

    ULONG64 singleHeap = 0;
    ULONG64 limit = 0;
    if (!parseHeapArgs(session, out, args, singleHeap, limit)) {
        return S_OK;
    }

    auto heaps = collectHeaps(session, out, limit, singleHeap);
    std::sort(heaps.begin(), heaps.end(), [](const HeapSummary& left, const HeapSummary& right) {
        return left.address < right.address;
    });

    out.heading("Heap Visualization");
    if (heaps.empty()) {
        return S_OK;
    }

    for (const auto& heap : heaps) {
        const ULONG64 maxChunks = configGetNumber("heap.vis.max_chunks", 160);
        const ULONG64 peekBytes = configGetNumber("heap.vis.peek_bytes", 32);
        const auto chunks = collectHeapChunks(
            session,
            out,
            heap.address,
            configGetNumber("heap.vis.max_segments", 16),
            maxChunks);
        const auto stats = summarizeChunks(chunks);
        const std::string title = "  heap " + formatHex(heap.index, 2) + "  " + formatAddress(heap.address) +
            "  chunks=" + formatHex(static_cast<ULONG64>(chunks.size())) +
            "  busy=" + formatHex(stats.busyCount) + " (0x" + formatHex(stats.busyBytes) + ")" +
            "  free=" + formatHex(stats.freeCount) + " (0x" + formatHex(stats.freeBytes) + ")";
        out.dmlLine(
            title,
            "  " + dmlColor("heap " + formatHex(heap.index, 2), "cyan") + "  " +
                dmlColor(formatAddress(heap.address), "white") + "  " +
                dmlColor("chunks=" + formatHex(static_cast<ULONG64>(chunks.size())), "gray") + "  " +
                dmlColor("busy=" + formatHex(stats.busyCount) + " (0x" + formatHex(stats.busyBytes) + ")", "green") + "  " +
                dmlColor("free=" + formatHex(stats.freeCount) + " (0x" + formatHex(stats.freeBytes) + ")", "yellow"));
        out.dmlLine(
            "  actions  [chunks] [segments] [flags] [validate]",
            "  " + dmlColor("actions", "gray") + "  " +
                dmlCommandLink("chunks", "!wef.heaps chunks " + formatAddress(heap.address)) + " " +
                dmlCommandLink("segments", "!wef.heaps segments " + formatAddress(heap.address)) + " " +
                dmlCommandLink("flags", "!wef.heaps flags " + formatAddress(heap.address)) + " " +
                dmlCommandLink("validate", "!wef.heaps validate " + formatAddress(heap.address)));

        if (chunks.empty()) {
            out.warning("no chunks found for heap " + formatAddress(heap.address) + "; LFH or symbols may hide backend chunks\n");
        } else {
            printGefStyleHeapLayout(session, out, chunks, peekBytes);
            if (static_cast<ULONG64>(chunks.size()) >= maxChunks) {
                out.warning("heap visualization may be truncated; raise heap.vis.max_chunks to show more chunks\n");
            }
        }
        out.blank();
    }
    return S_OK;
}

}
