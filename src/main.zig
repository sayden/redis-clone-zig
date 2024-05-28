const std = @import("std");
const net = std.net;
const Mutex = std.Thread.Mutex;
const testing = std.testing;
const fmt = std.fmt;

const Commands = enum {
    PING,
    ECHO,
    SET,
    SET_EXPIRY,
    GET,
    QUIT,
    CONFIG_SET,
    CONFIG_GET,
    KEYS,
};

const Quit = struct {
    mutex: Mutex = Mutex{},
    quit: bool = false,
};

const Errors = error{InvalidCharacter};

const CommandEnd = "\n";
const TokenSplit = "\r\n";
var quit = Quit{};

const KvArray = struct {
    hashmap: std.StringHashMap([]u8),
    config: std.StringHashMap([]u8),
    expiries: std.StringHashMap(i64),

    alloc: std.mem.Allocator,

    mutex: Mutex = Mutex{},
    cfgMutex: Mutex = Mutex{},

    const Errors = error{NotFound};

    pub fn init(alloc: std.mem.Allocator) KvArray {
        return KvArray{
            .hashmap = std.StringHashMap([]u8).init(alloc),
            .config = std.StringHashMap([]u8).init(alloc),
            .expiries = std.StringHashMap(i64).init(alloc),
            .alloc = alloc,
            .mutex = Mutex{},
        };
    }
    pub fn deinit(self: *KvArray) void {
        self.hashmap.deinit();
    }

    // *2\r\n$4\r\nECHO\r\n$3\r\nhey\r\n
    pub fn keys(self: *KvArray, c: net.Server.Connection) !void {
        const writer = c.stream.writer();

        self.mutex.lock();
        defer self.mutex.unlock();

        const size = self.hashmap.count();
        try fmt.format(writer, "*{d}\r\n", .{@as(u32, size)});

        var iter = self.hashmap.keyIterator();
        while (iter.next()) |key| {
            try fmt.format(writer, "${d}\r\n{s}\r\n", .{ key.*.len, key.* });
        }
    }

    pub fn put(self: *KvArray, key: []u8, value: []u8, expiry: ?i64) !void {
        const _key = try self.alloc.alloc(u8, key.len);
        errdefer self.alloc.free(_key);

        const _value = try self.alloc.alloc(u8, value.len);
        errdefer self.alloc.free(_value);

        @memcpy(_key, key);
        @memcpy(_value, value);

        self.mutex.lock();
        defer self.mutex.unlock();

        try self.hashmap.put(_key, _value);
        if (expiry) |e| {
            try self.expiries.put(_key, e);
        }
    }

    pub fn configSet(self: *KvArray, key: []u8, value: []u8) !void {
        const _key = try self.alloc.alloc(u8, key.len);
        errdefer self.alloc.free(_key);

        const _value = try self.alloc.alloc(u8, value.len);
        errdefer self.alloc.free(_value);

        @memcpy(_key, key);
        @memcpy(_value, value);

        self.cfgMutex.lock();
        defer self.cfgMutex.unlock();

        try self.config.put(_key, _value);
    }

    pub fn configGet(self: *KvArray, key: []u8) ?[]u8 {
        self.cfgMutex.lock();
        defer self.cfgMutex.unlock();

        const value = self.config.get(key) orelse {
            return null;
        };

        return value;
    }

    pub fn get(self: *KvArray, key: []u8) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const value = self.hashmap.get(key) orelse {
            return null;
        };
        const expiration = self.expiries.get(key) orelse {
            return value;
        };
        const now = std.time.milliTimestamp();
        if (expiration <= now) {
            std.debug.print("Key expired: {s}\n", .{key});
            _ = self.hashmap.remove(key);
            _ = self.expiries.remove(key);
            return null;
        }

        return value;
    }
};

fn checkMemoryLeak(gpa: *std.heap.GeneralPurposeAllocator(.{})) void {
    const res = gpa.deinit();
    switch (res) {
        std.heap.Check.ok => {},
        std.heap.Check.leak => std.debug.print("Memory leak detected\n", .{}),
    }
}

fn handleConnection(connection: net.Server.Connection, kvs: *KvArray) !void {
    const conReader = connection.stream.reader();

    var tokens: [128][]u8 = undefined;
    var commands: [32]?[]u8 = undefined;
    for (0..commands.len) |i| {
        commands[i] = null;
    }

    while (true) {
        var buffer: [1024]u8 = undefined;
        if (try conReader.read(&buffer) > 0) {
            try splitLines(&buffer, &commands);
            for (commands) |command| {
                if (command) |cmd| {
                    const n = try bytesToTokens(cmd, &tokens);
                    try executeCommand(&tokens, n, connection, kvs);
                } else {
                    break;
                }
            }
        }
    }
}

fn executeCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    switch (tokensToCommands(tokens, n)) {
        Commands.PING => try connection.stream.writeAll("+PONG\r\n"),
        Commands.ECHO => try echoCommand(tokens, n, connection),
        Commands.SET => try setCommand(tokens, n, connection, kvs),
        Commands.GET => try getCommand(tokens, n, connection, kvs),
        Commands.SET_EXPIRY => try setCommand(tokens, n, connection, kvs),
        Commands.CONFIG_GET => try configGetCommand(tokens, n, connection, kvs),
        Commands.CONFIG_SET => try configSetCommand(tokens, n, connection, kvs),
        Commands.KEYS => try keysCommand(connection, kvs),
        Commands.QUIT => {
            quit.mutex.lock();
            quit.quit = true;
            quit.mutex.unlock();
        },
    }
}

fn keysCommand(c: net.Server.Connection, kvs: *KvArray) !void {
    try kvs.keys(c);
}

fn configSetCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n < 9) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.InvalidNumberArguments;
    }

    try kvs.configSet(tokens[4], tokens[6]);

    // kvs.iter += 1;
    try fmt.format(connection.stream.writer(), "+OK\r\n", .{});
}

fn configGetCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n != 7) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.Invalid;
    }

    if (kvs.configGet(tokens[6])) |val| {
        try fmt.format(connection.stream.writer(), "*2\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{
            tokens[6].len,
            tokens[6],
            val.len,
            val,
        });

        return;
    }

    try fmt.format(connection.stream.writer(), "$-1\r\n", .{});

    return;
}

// *2\r\n$3\r\nGET\r\n$6\r\nbanana\r\n
// *2 $3 GET $6 banana
//  0  1   2  3      4
fn getCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n != 5) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.Invalid;
    }

    if (kvs.get(tokens[4])) |val| {
        try fmt.format(connection.stream.writer(), "${d}\r\n{s}\r\n", .{ val.len, val });
        return;
    }

    try fmt.format(connection.stream.writer(), "$-1\r\n", .{});

    return;
}

// *2\r\n$4\r\nECHO\r\n$3\r\nhey\r\n
// *2\r\n$3\r\nGET\r\n$9\r\nraspberry\r\n
// *2 $3 GET $3 foo
// *2 $3 SET $3 foo $3 bar
// *2 $3 SET $3 foo $3 bar $2 PX $3 100
//
//  0  1   2  3   4  5   6  7  8  9  10
fn setCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n < 7) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.InvalidNumberArguments;
    }

    if (n == 11) {
        toUpper(tokens[8]);
        if (str_eq(tokens[8], "PX")) {
            const now = std.time.milliTimestamp();
            const expiry = try fmt.parseInt(i64, tokens[10], 10);
            std.debug.print("Setting expiration (now: {d}, or: {d}): {d}\n", .{ expiry + now, expiry, now });
            try kvs.put(tokens[4], tokens[6], expiry + now);
        }
    } else {
        try kvs.put(tokens[4], tokens[6], null);
    }

    // kvs.iter += 1;
    try fmt.format(connection.stream.writer(), "+OK\r\n", .{});
}

fn echoCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection) !void {
    if (n != 5) {
        return error.Invalid;
    }

    try fmt.format(connection.stream.writer(), "${d}\r\n{s}\r\n", .{ tokens[4].len, tokens[4] });
}

fn tokensToCommands(tokens: *[128][]u8, _: usize) Commands {
    toUpper(tokens[2]);

    if (str_eq(tokens[2], "PING")) {
        return Commands.PING;
    } else if (str_eq(tokens[2], "ECHO")) {
        return Commands.ECHO;
    } else if (str_eq(tokens[2], "SET")) {
        if (tokens.len == 10 and str_eq(toUpper(tokens[8]), "PX")) {
            return Commands.SET_EXPIRY;
        } else {
            return Commands.SET;
        }
        return Commands.SET;
    } else if (str_eq(tokens[2], "GET")) {
        return Commands.GET;
    } else if (str_eq(tokens[2], "QUIT")) {
        return Commands.QUIT;
    } else if (str_eq(tokens[2], "KEYS")) {
        return Commands.KEYS;
    } else if (str_eq(tokens[2], "CONFIG")) {
        toUpper(tokens[4]);
        if (str_eq(tokens[4], "SET")) {
            return Commands.CONFIG_SET;
        } else if (str_eq(tokens[4], "GET")) {
            return Commands.CONFIG_GET;
        }
        return Commands.PING;
    }

    return Commands.PING;
}

fn bytesToTokens(bytes: []u8, tokens: *[128][]u8) !usize {
    var left: usize = 0;
    var tokenCount: usize = 0;

    // std.debug.print("Parsing: '{s}'\n", .{bytes});

    for (bytes, 0..) |c, i| {
        switch (c) {
            '\r' => {
                if (bytes.len > i and bytes[i + 1] == '\n') {
                    const token = bytes[left..i];
                    tokens[tokenCount] = token;
                    left = i + 2;
                    tokenCount += 1;
                }
            },
            '*' => {},
            else => {},
        }
    }

    // for (0..tokenCount) |i| {
    //     std.debug.print("Found: '{s}'\n", .{tokens[i]});
    // }

    return tokenCount;
}

fn splitLines(buf: []u8, commands: *[32]?[]u8) !void {
    var left: usize = 0;
    var items: usize = 0;

    for (buf, 0..) |c, i| {
        if (c == '\n' and i != 0 and buf[i - 1] != '\r') {
            commands[items] = buf[left..i];
            items += 1;
            left = i + 1;
        }
    }

    commands[items] = buf[left..];
}

fn toUpper(s: []u8) void {
    for (s, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') {
            s[i] -= 32;
        }
    }
}

fn str_eq(a: []u8, b: []const u8) bool {
    if (a.len != b.len) {
        return false;
    }

    for (a, b) |i, j| {
        if (i != j) {
            return false;
        }
    }

    return true;
}

pub fn main() !void {
    const address = try net.Address.resolveIp("127.0.0.1", 6379);

    var listener = try address.listen(.{
        .reuse_address = true,
        .force_nonblocking = true,
    });
    defer listener.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer checkMemoryLeak(&gpa);
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    const alloc = arena.allocator();
    defer arena.deinit();

    var argsIterator = try std.process.ArgIterator.initWithAllocator(alloc);
    defer argsIterator.deinit();

    var kvs = KvArray.init(alloc);
    defer kvs.deinit();

    while (argsIterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dir")) {
            const val = argsIterator.next() orelse {
                std.debug.print("Missing argument for --dir\n", .{});
                return error.MissingArgument;
            };
            try kvs.configSet(@constCast("dir"), @constCast(val));
        } else if (std.mem.eql(u8, arg, "--dbfilename")) {
            const val = argsIterator.next() orelse {
                std.debug.print("Missing argument for --dir\n", .{});
                return error.MissingArgument;
            };
            try kvs.configSet(@constCast("dbfilename"), @constCast(val));
        }
    }

    const dir = kvs.configGet(@constCast("dir"));
    const dbfilename = kvs.configGet(@constCast("dbfilename"));

    try loadDBFile(&kvs, dir, dbfilename);
    std.debug.print("Finished loaded db\n", .{});

    while (true) {
        quit.mutex.lock();
        if (quit.quit) {
            std.debug.print("Shutting down\n", .{});
            quit.mutex.unlock();
            break;
        }
        quit.mutex.unlock();

        if (listener.accept()) |connection| {
            var t = try std.Thread.spawn(.{}, handleConnection, .{ connection, &kvs });
            t.detach();
        } else |_| {
            std.time.sleep(1000000);
        }
    }
}

const Length = enum {
    Next6BitsAreLength,
    AddByteForLength,
    Next4BytesAreLength,
    Special8BitInt,
    Special16BitInt,
    Special32BitInt,
    SpecialCompressed,
    Unknown,
};

const EncodingType = enum {
    Bits8,
    Bits16,
    Bits32,
    String,
    CompressedString,
};

fn readDB(db: []align(std.mem.page_size) u8, kvs: *KvArray) !void {
    const magic = db[0..5];

    std.debug.print("\ndb: '{s}'\n", .{magic});
    const version = db[5..9];
    std.debug.print("Version Number: '{s}'\n", .{version});

    var pivot: usize = 9;
    var block: RDBType = undefined;

    while (true) {
        if (pivot >= db.len) {
            break;
        }

        block = getRDBBlockType(db[pivot]);
        pivot += 1;

        switch (block) {
            RDBType.Auxiliary => {
                pivot += try printAuxiliary(db[pivot..]);
            },
            RDBType.DatabaseSelector => {
                std.debug.print("Database Selector: {X} \n", .{db[pivot]}); // Database number
                pivot += 1;
            },
            RDBType.ResizeDB => {
                pivot += try printResizeDB(db[pivot..]);
            },
            RDBType.EOF => {
                std.debug.print("CRC64: {d} \n", .{std.mem.readVarInt(u64, db[pivot .. pivot + 8], .little)});
                pivot += 8;
                return;
            },
            RDBType.ValueType => {
                // A value type block requires to interpret again the previous byte to get the actual value type
                // that's why we need to back the pivot by 1 in the next line
                pivot += try loadKv(db[pivot - 1 ..], kvs, null);
                pivot -= 1; // we need to back the byte we substracted above too
            },
            RDBType.ExpireTimeMs => {
                const n = std.mem.readVarInt(i64, db[pivot .. pivot + 8], .little);
                pivot += 8;
                pivot += try loadKv(db[pivot..], kvs, n);
            },
            RDBType.ExpireTimeSeconds => {
                const n = std.mem.readVarInt(u32, db[pivot .. pivot + 4], .little);
                pivot += 4;
                pivot += try loadKv(db[pivot..], kvs, @as(i64, n));
            },
            else => {
                std.debug.print("Unknown block type: {}\n", .{block});
            },
        }
    }
}

fn printAuxiliary(db: []u8) !usize {
    var pivot: usize = 0;

    var length = getLengthFromByte(db[pivot]);
    var str = try getEncodedString(db[pivot..], length);
    pivot += getOffsetValue(length) + str.len;

    std.debug.print("{s} -> ", .{str});

    length = getLengthFromByte(db[pivot]);
    switch (length) {
        Length.Next6BitsAreLength, Length.AddByteForLength, Length.Next4BytesAreLength => {
            str = try getEncodedString(db[pivot..], length);
            pivot += getOffsetValue(length) + str.len;
            std.debug.print(" {s}\n", .{str});
        },
        Length.Special8BitInt, Length.Special16BitInt, Length.Special32BitInt => {
            const n = try getIntegerEncodedAsString(db[pivot..], length);
            pivot += getOffsetValue(length);
            std.debug.print(" {d}\n", .{n});
        },
        else => {
            std.debug.print("Unknown length encoding: {}\n", .{length});
        },
    }

    return pivot;
}

fn loadKv(db: []u8, kvs: *KvArray, expiry: ?i64) !usize {
    var pivot: usize = 0;
    const vt = getValueType(db[pivot]);
    pivot += 1;

    switch (vt) {
        ValueType.String => {
            var length = getLengthFromByte(db[pivot]);
            const key = try getEncodedString(db[pivot..], length);
            pivot += getOffsetValue(length) + key.len;

            length = getLengthFromByte(db[pivot]);
            const val = try getEncodedString(db[pivot..], length);
            pivot += getOffsetValue(length) + val.len;

            if (expiry) |e| {
                std.debug.print("Key: {s}, Value: {s}, Expiry: {d}\n", .{ key, val, e });
            } else {
                std.debug.print("Key: {s}, Value: {s}\n", .{ key, val });
            }
            try kvs.put(key, val, expiry);
        },
        else => {
            std.debug.print("Unknown value type: {}\n", .{vt});
        },
    }

    return pivot;
}

fn loadDBFile(kvs: *KvArray, dir: ?[]u8, dbfilename: ?[]u8) !void {
    if (dbfilename) |filename| {
        var file: std.fs.File = undefined;

        if (dir) |d| {
            var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const filepath = try fmt.bufPrint(&buf, "{s}/{s}", .{ d, filename });

            std.debug.print("Loading file: '{s}'\n", .{filepath});

            file = std.fs.openFileAbsolute(filepath, .{ .mode = .read_only }) catch {
                std.debug.print("File not found: '{s}'\n", .{filepath});
                return;
            };
        } else {
            std.debug.print("Loading file: './{s}'\n", .{filename});
            file = std.fs.cwd().openFile(filename, .{ .mode = .read_only }) catch {
                std.debug.print("File not found: '{s}'\n", .{filename});
                return error.FileNotFound;
            };
        }

        defer file.close();
        const stat = try file.stat();

        const db = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .SHARED }, file.handle, 0);
        defer std.posix.munmap(db);

        try readDB(db, kvs);
        return;
    }

    return;
}

fn getIntegerEncodedAsString(buf: []u8, length: Length) !usize {
    switch (length) {
        Length.Special8BitInt => {
            return @as(usize, buf[1]);
        },
        Length.Special16BitInt => {
            const n = std.mem.readVarInt(u16, buf[1..3], .little);
            return @as(usize, n);
        },
        Length.Special32BitInt => {
            const n = std.mem.readVarInt(u32, buf[1..5], .little);
            return @as(usize, n);
        },
        else => return error.UnknownIntegerStringEncoding,
    }
}

fn getEncodedString(buf: []u8, length: Length) ![]u8 {
    return switch (length) {
        Length.Next6BitsAreLength => {
            const n: usize = buf[0] & 0b00111111;
            return buf[1 .. 1 + n];
        },
        Length.AddByteForLength => {
            const n: u8 = buf[0] & 0b00111111;
            const nn: [8]u8 = .{ 0, 0, 0, 0, 0, 0, n, buf[1] };
            const size = std.mem.readInt(usize, &nn, .big);
            return buf[2 .. 2 + size];
        },
        Length.Next4BytesAreLength => {
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            const size = std.mem.readInt(usize, &nn, .big);
            return buf[5 .. 5 + size];
        },
        else => return error.UnknownStringEncoding,
    };
}

fn getOffsetValue(l: Length) usize {
    return switch (l) {
        Length.Next6BitsAreLength => 1,
        Length.AddByteForLength => 2,
        Length.Next4BytesAreLength => 5,
        Length.Special8BitInt => 2,
        Length.Special16BitInt => 3,
        Length.Special32BitInt => 5,
        Length.SpecialCompressed => 0,
        else => 0,
    };
}

fn getLength(buf: []u8, l: Length) !usize {
    return switch (l) {
        Length.Next6BitsAreLength => {
            return @as(usize, buf[0] & 0b00111111);
        },
        Length.AddByteForLength => {
            const n: u8 = buf[0] & 0b00111111;
            const nn: [8]u8 = .{ 0, 0, 0, 0, 0, 0, n, buf[1] };
            return std.mem.readInt(usize, &nn, .big);
        },
        Length.Next4BytesAreLength => {
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            return std.mem.readInt(usize, &nn, .big);
        },
        Length.Special8BitInt => {
            // Integer as a string: 8-bit
            const n = try fmt.parseInt(u8, buf[1..2], 10);
            return @as(usize, n);
        },
        Length.Special16BitInt => {
            // Integer as a string: 16-bit
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], 0, 0 };
            return try fmt.parseInt(usize, &nn, 10);
        },
        Length.Special32BitInt => {
            // Integer as a string: 32-bit
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            return try fmt.parseInt(usize, &nn, 10);
        },
        Length.SpecialCompressed => {
            return error.CompressedStringNotImplemented;
        },
        else => return error.UnknownLengthEncoding,
    };
}

fn getLengthFromByte(byte: u8) Length {
    const firstTwo = byte & 0b11000000;
    return switch (firstTwo) {
        0b00000000 => Length.Next6BitsAreLength,
        0b01000000 => Length.AddByteForLength,
        0b10000000 => Length.Next4BytesAreLength,
        0b11000000 => {
            return switch (byte) {
                0b11000000 => Length.Special8BitInt,
                0b11000001 => Length.Special16BitInt,
                0b11000010 => Length.Special32BitInt,
                0b11000011 => Length.SpecialCompressed,
                else => Length.Unknown,
            };
        },
        else => Length.Unknown,
    };
}

const RDBType = enum {
    Auxiliary,
    DatabaseSelector,
    EOF,
    ExpireTimeMs,
    ExpireTimeSeconds,
    ResizeDB,
    ValueType,
    Unknown,
};

fn getRDBBlockType(b: u8) RDBType {
    return switch (b) {
        0xFA => RDBType.Auxiliary,
        0xFE => RDBType.DatabaseSelector,
        0xFF => RDBType.EOF,
        0xFC => RDBType.ExpireTimeMs,
        0xFD => RDBType.ExpireTimeSeconds,
        0xFB => RDBType.ResizeDB,
        0...14 => RDBType.ValueType,
        else => RDBType.Unknown,
    };
}

const ValueType = enum {
    String,
    List,
    Set,
    SortedSet,
    Hash,
    ZipMap,
    ZipList,
    IntSet,
    SortedSetZipList,
    HashZipList,
    Unknown,
};

fn getValueType(b: u8) ValueType {
    switch (b) {
        0x00 => return ValueType.String,
        0x01 => return ValueType.List,
        0x02 => return ValueType.Set,
        0x03 => return ValueType.SortedSet,
        0x04 => return ValueType.Hash,
        0x09 => return ValueType.ZipMap,
        0x0A => return ValueType.ZipList,
        0x0B => return ValueType.IntSet,
        0x0C => return ValueType.SortedSetZipList,
        0x0D => return ValueType.HashZipList,
        else => return ValueType.Unknown,
    }
}

fn printResizeDB(header: []u8) !usize {
    std.debug.print("ResizeDB: ", .{}); // Database number

    var pivot: usize = 0;
    var length = getLengthFromByte(header[pivot]);
    var lengthData = try getLength(header, length); // Database hash table size
    std.debug.print("\n\tHash Table size: {d}", .{lengthData});
    pivot += getOffsetValue(length);

    length = getLengthFromByte(header[pivot]);
    lengthData = try getLength(header[pivot..], length); // Database hash table size
    std.debug.print("\n\tExpiry Hash table size: {d}\n", .{lengthData});
    pivot += getOffsetValue(length);

    return pivot;
}

test "toUpper" {
    var alloc = testing.allocator;
    const ar = try alloc.alloc(u8, 5);
    defer alloc.free(ar);

    @memcpy(ar, "hello");
    toUpper(ar);
    try testing.expectEqualStrings(ar, "HELLO");
}

test "parseTokens" {
    var tokens: [128][]u8 = undefined;
    var bytes: [64]u8 = undefined;
    const msg = "hello\r\nworld\r\n";
    @memcpy(bytes[0..msg.len], msg);
    _ = try bytesToTokens(bytes[0..msg.len], &tokens);

    try testing.expectEqualStrings(tokens[0], "hello");
    try testing.expectEqualStrings(tokens[1], "world");

    const msg2 = "*2\r\n$3\r\nGET\r\n$5\r\ngrape\r\n";
    @memcpy(bytes[0..msg2.len], msg2);

    var tokens2: [128][]u8 = undefined;
    var n = bytesToTokens(bytes[0..msg2.len], &tokens2);
    try testing.expectEqual(n, 5);

    const msg3 = "*2\r\n$3\r\nGET\r\n$6\r\nbanana\r\n";
    n = bytesToTokens(@constCast(msg3), &tokens2);
    try testing.expectEqual(5, n);
}

test "ConcurrentHash" {
    const str = "hello";
    var hash = std.StringHashMap([]const u8).init(testing.allocator);
    defer hash.deinit();
    try hash.put(str, str);
}

test "split_commands" {
    const msg = "*1\r\n$9\r\nPING\nPING\r\n";
    var buffer: [64]u8 = undefined;
    @memcpy(buffer[0..msg.len], msg);

    var commands: [32]?[]u8 = undefined;
    for (0..commands.len) |i| {
        commands[i] = null;
    }

    _ = try splitLines(&buffer, &commands);

    try testing.expectEqualSlices(u8, "*1\r\n$9\r\nPING", commands[0].?);
    try testing.expectEqualSlices(u8, "PING\r\n", commands[1].?[0..6]);

    try testing.expect(commands[2] == null);

    const msg2 = "*3\r\n$3\r\nSET\r\n$9\r\nraspberry\r\n$5\r\nmango\r\n";
    @memcpy(buffer[0..msg2.len], msg2);
    for (0..commands.len) |i| {
        commands[i] = null;
    }
    _ = try splitLines(buffer[0..msg2.len], &commands);
    try testing.expectEqualSlices(u8, msg2, commands[0].?);
    try testing.expect(commands[1] == null);
}

test "loadDB" {
    var kvs = KvArray.init(std.testing.allocator);
    defer kvs.deinit();

    const db = "/home/projects/codecrafters-redis-zig";
    const dbfilename = "dump.rdb";
    try loadDBFile(&kvs, @constCast(db), @constCast(dbfilename));

    _ = try kvs.get(@constCast("mariete"));
    _ = try kvs.get(@constCast("ula"));
}
