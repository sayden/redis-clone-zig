const std = @import("std");
const net = std.net;
const Mutex = std.Thread.Mutex;

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

    pub fn keys(self: *KvArray, c: net.Server.Connection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const writer = c.stream.writer();
        const size = self.hashmap.count();
        try std.fmt.format(writer, "*{d}\r\n", .{size});

        var iter = self.hashmap.keyIterator();
        while (iter.next()) |key| {
            try std.fmt.format(writer, "${d}\r\n{s}\r\n", .{ key.len, key });
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

    pub fn configGet(self: *KvArray, key: []u8) ![]u8 {
        self.cfgMutex.lock();
        defer self.cfgMutex.unlock();

        const value = self.config.get(key) orelse {
            return KvArray.Errors.NotFound;
        };

        return value;
    }

    pub fn get(self: *KvArray, key: []u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const value = self.hashmap.get(key) orelse {
            return KvArray.Errors.NotFound;
        };
        const expiration = self.expiries.get(key) orelse {
            return value;
        };
        const now = std.time.milliTimestamp();
        if (expiration <= now) {
            _ = self.hashmap.remove(key);
            _ = self.expiries.remove(key);
            return KvArray.Errors.NotFound;
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
            connection.stream.close();
            quit.mutex.unlock();
        },
    }
}

fn keysCommand(connection: net.Server.Connection, kvs: *KvArray) !void {
    try kvs.keys(connection);
    connection.stream.close();
}

fn configSetCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n < 9) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.InvalidNumberArguments;
    }

    try kvs.configSet(tokens[4], tokens[6]);

    // kvs.iter += 1;
    try std.fmt.format(connection.stream.writer(), "+OK\r\n", .{});
    connection.stream.close();
}

fn configGetCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n != 7) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.Invalid;
    }

    const val = kvs.configGet(tokens[6]) catch {
        try std.fmt.format(connection.stream.writer(), "$-1\r\n", .{});
        return;
    };

    try std.fmt.format(connection.stream.writer(), "*2\r\n${d}\r\n{s}\r\n${d}\r\n{s}\r\n", .{ tokens[6].len, tokens[6], val.len, val });

    connection.stream.close();

    return;
}

fn getCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n != 5) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.Invalid;
    }

    const val = kvs.get(tokens[4]) catch {
        try std.fmt.format(connection.stream.writer(), "$-1\r\n", .{});
        return;
    };

    try std.fmt.format(connection.stream.writer(), "${d}\r\n{s}\r\n", .{ val.len, val });

    connection.stream.close();

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
            const expiry = try std.fmt.parseInt(i64, tokens[10], 10);
            try kvs.put(tokens[4], tokens[6], expiry + now);
        }
    } else {
        try kvs.put(tokens[4], tokens[6], null);
    }

    // kvs.iter += 1;
    try std.fmt.format(connection.stream.writer(), "+OK\r\n", .{});
}

fn echoCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection) !void {
    if (n != 5) {
        return error.Invalid;
    }

    try std.fmt.format(connection.stream.writer(), "${d}\r\n{s}\r\n", .{ tokens[4].len, tokens[4] });
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
    std.debug.print("Logs from your program will appear here!\n", .{});

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
            try loadDBFile(val, &kvs);
            try kvs.configSet(@constCast("dbfilename"), @constCast(val));
        }
    }

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

const LengthEncoding = struct {
    // How many bytes to skip
    skip: u8,

    str: []u8,

    // To signal if str is an integer as a string, for example
    encType: EncodingType,
    lengthType: Length,

    pub fn accLen(self: @This()) usize {
        return self.str.len + self.skip;
    }
};

fn loadDBFile(filename: []const u8, kvs: *KvArray) !void {
    const file = try std.fs.cwd().openFile(filename, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();

    const db = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .SHARED }, file.handle, 0);
    defer std.posix.munmap(db);

    var pivot: usize = 0;
    while (true) {
        const key = try getEncodedString(db[pivot..]); // 1-ula, 2-mario
        pivot += key.accLen();

        const val = try getEncodedString(db[pivot..]); // 1-korn, 2-caster
        pivot += val.accLen();

        try kvs.put(key.str, val.str, null);

        if (db[pivot] != 0x00) {
            break;
        }
        pivot += 1;
    }
}

fn getEncodedString(buf: []u8) !LengthEncoding {
    const length = getLengthFromByte(buf[0]);

    return switch (length) {
        Length.Next6BitsAreLength => {
            const n: usize = buf[0] & 0b00111111;
            return LengthEncoding{ .skip = 1, .str = buf[1 .. 1 + n], .encType = EncodingType.String, .lengthType = length };
        },
        Length.AddByteForLength => {
            const n: u8 = buf[0] & 0b00111111;
            const nn: [8]u8 = .{ 0, 0, 0, 0, 0, 0, n, buf[1] };
            const size = std.mem.readInt(usize, &nn, .big);
            return LengthEncoding{ .skip = 2, .str = buf[2 .. 2 + size], .encType = EncodingType.String, .lengthType = length };
        },
        Length.Next4BytesAreLength => {
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            const size = std.mem.readInt(usize, &nn, .big);
            return LengthEncoding{ .skip = 5, .str = buf[5 .. 5 + size], .encType = EncodingType.String, .lengthType = length };
        },
        Length.Special8BitInt => {
            return LengthEncoding{ .skip = 1, .str = buf[1..2], .encType = EncodingType.Bits8, .lengthType = length };
        },
        Length.Special16BitInt => {
            return LengthEncoding{ .skip = 1, .str = buf[1..3], .encType = EncodingType.Bits16, .lengthType = length };
        },
        Length.Special32BitInt => {
            return LengthEncoding{ .skip = 1, .str = buf[1..5], .encType = EncodingType.Bits32, .lengthType = length };
        },
        Length.SpecialCompressed => {
            // TODO: compressed string
            return error.CompressedStringNotImplemented;
        },
        else => return error.UnknownLengthEncoding,
    };
}

const LengthData = struct {
    length: usize,
    skip: usize,
};

fn getLength(buf: []u8) !LengthData {
    const length = getLengthFromByte(buf[0]);
    return switch (length) {
        Length.Next6BitsAreLength => {
            return LengthData{ .length = @as(usize, buf[0] & 0b00111111), .skip = 1 };
        },
        Length.AddByteForLength => {
            const n: u8 = buf[0] & 0b00111111;
            const nn: [8]u8 = .{ 0, 0, 0, 0, 0, 0, n, buf[1] };
            return LengthData{ .length = std.mem.readInt(usize, &nn, .big), .skip = 2 };
        },
        Length.Next4BytesAreLength => {
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            return LengthData{ .length = std.mem.readInt(usize, &nn, .big), .skip = 5 };
        },
        Length.Special8BitInt => {
            // Integer as a string: 8-bit
            const n = try std.fmt.parseInt(u8, buf[1..2], 10);
            return LengthData{ .length = @as(usize, n), .skip = 1 };
        },
        Length.Special16BitInt => {
            // Integer as a string: 16-bit
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], 0, 0 };
            return LengthData{ .length = try std.fmt.parseInt(usize, &nn, 10), .skip = 3 };
        },
        Length.Special32BitInt => {
            // Integer as a string: 32-bit
            const nn: [8]u8 = .{ 0, 0, 0, 0, buf[1], buf[2], buf[3], buf[4] };
            return LengthData{ .length = try std.fmt.parseInt(usize, &nn, 10), .skip = 5 };
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
        else => RDBType.Unknown,
    };
}

fn printAuxiliary(header: []u8) !usize {
    var pivot: usize = 0;

    std.debug.print("FA: ", .{});

    var lenEnc = try getEncodedString(header[pivot..]);
    std.debug.print("{s} -> ", .{lenEnc.str});
    pivot += lenEnc.accLen();

    lenEnc = try getEncodedString(header[pivot..]);
    std.debug.print("'{s}'\n", .{lenEnc.str});
    pivot += lenEnc.accLen();

    return pivot;
}

fn printKvs(buf: []u8) !usize {
    var pivot: usize = 0;
    var lenEnc: LengthEncoding = undefined;
    while (true) {
        lenEnc = try getEncodedString(buf[pivot..]); // 1-ula, 2-mario
        pivot += lenEnc.accLen();
        std.debug.print("'{s}', ", .{lenEnc.str});

        lenEnc = try getEncodedString(buf[pivot..]); // 1-korn, 2-caster
        pivot += lenEnc.accLen();
        std.debug.print("'{s}'\n", .{lenEnc.str});

        if (buf[pivot] != 0x00) {
            break;
        }
        pivot += 1;
    }
    return pivot;
}

fn printResizeDB(header: []u8) !usize {
    std.debug.print("ResizeDB: ", .{}); // Database number

    var pivot: usize = 0;
    var lengthData = try getLength(header); // Database hash table size
    std.debug.print("\n\tHash Table size: {d}", .{lengthData.length});
    // FIXME:
    pivot += lengthData.skip;

    lengthData = try getLength(header[pivot..]); // Database hash table size
    std.debug.print("\n\tExpiry Hash table size: {d}\n", .{lengthData.length});
    // FIXME:
    pivot += lengthData.skip;

    if (header[pivot] == 0x00) {
        pivot += 1;
        return pivot;
    }

    return error.UnexpectedByteInResizeDB;
}

test "toUpper" {
    var alloc = std.testing.allocator;
    const ar = try alloc.alloc(u8, 5);
    defer alloc.free(ar);

    @memcpy(ar, "hello");
    toUpper(ar);
    try std.testing.expectEqualStrings(ar, "HELLO");
}

test "parseTokens" {
    var tokens: [128][]u8 = undefined;
    var bytes: [64]u8 = undefined;
    const msg = "hello\r\nworld\r\n";
    @memcpy(bytes[0..msg.len], msg);
    _ = try bytesToTokens(bytes[0..msg.len], &tokens);

    try std.testing.expectEqualStrings(tokens[0], "hello");
    try std.testing.expectEqualStrings(tokens[1], "world");

    const msg2 = "*2\r\n$3\r\nGET\r\n$5\r\ngrape\r\n";
    @memcpy(bytes[0..msg2.len], msg2);

    var tokens2: [128][]u8 = undefined;
    const n = bytesToTokens(bytes[0..msg2.len], &tokens2);
    try std.testing.expectEqual(n, 5);
}

test "ConcurrentHash" {
    const str = "hello";
    var hash = std.StringHashMap([]const u8).init(std.testing.allocator);
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

    try std.testing.expectEqualSlices(u8, "*1\r\n$9\r\nPING", commands[0].?);
    try std.testing.expectEqualSlices(u8, "PING\r\n", commands[1].?[0..6]);

    try std.testing.expect(commands[2] == null);

    const msg2 = "*3\r\n$3\r\nSET\r\n$9\r\nraspberry\r\n$5\r\nmango\r\n";
    @memcpy(buffer[0..msg2.len], msg2);
    for (0..commands.len) |i| {
        commands[i] = null;
    }
    _ = try splitLines(buffer[0..msg2.len], &commands);
    try std.testing.expectEqualSlices(u8, msg2, commands[0].?);
    try std.testing.expect(commands[1] == null);
}

test "getLengthEncoding" {
    var hello: [5]u8 = undefined;
    @memcpy(&hello, "hello");
    hello[0] = 0b00000100;
    var n = try getEncodedString(&hello);
    try std.testing.expectEqual(4, n.str.len);
    try std.testing.expectEqual(1, n.skip);
    try std.testing.expectEqualStrings("ello", n.str);
    hello[0] = 0b01000000;
    hello[1] = 0b00000001;
    n = try getEncodedString(&hello);
    try std.testing.expectEqual(1, n.str.len);
    try std.testing.expectEqual(2, n.skip);
    try std.testing.expectEqualStrings("l", n.str);
    hello[0] = 0b11000000;
    hello[1] = 64;
    n = try getEncodedString(&hello);
    try std.testing.expectEqual(1, n.str.len);
    try std.testing.expectEqual(1, n.skip);
    try std.testing.expectEqual(@as(u8, 64), n.str[1 - n.str.len]);
}

test "parseRdbFilev1" {
    const dump = try std.fs.cwd().openFile("dump.rdb", .{ .mode = .read_only });
    defer dump.close();

    const stat = try dump.stat();

    const header = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .SHARED }, dump.handle, 0);
    defer std.posix.munmap(header);

    const magic = header[0..5];
    std.debug.print("\nHeader: '{s}'\n", .{magic});
    const version = header[5..9];
    std.debug.print("Version Number: '{s}'\n", .{version});

    var pivot: usize = 9;
    var block: RDBType = undefined;

    while (true) {
        if (pivot >= header.len) {
            break;
        }
        block = getRDBBlockType(header[pivot]);
        pivot += 1;
        switch (block) {
            RDBType.Auxiliary => {
                pivot += try printAuxiliary(header[pivot..]);
            },
            RDBType.DatabaseSelector => {
                std.debug.print("Database Selector: {X} \n", .{header[pivot]}); // Database number
                pivot += 1;
            },
            RDBType.ResizeDB => {
                pivot += try printResizeDB(header[pivot..]);
                pivot += try printKvs(header[pivot..]);
            },
            RDBType.EOF => {
                std.debug.print("EOF, ", .{}); // Database number
                std.debug.print("CRC64: {X}. \n", .{header[pivot .. pivot + 8]});
                pivot += 8;
                break;
            },
            else => {},
        }
    }
}
