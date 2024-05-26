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
        Commands.QUIT => {
            quit.mutex.lock();
            quit.quit = true;
            connection.stream.close();
            quit.mutex.unlock();
        },
    }
}

fn configSetCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n < 9) {
        std.debug.print("Unexpected number of arguments {}\n", .{n});
        return error.InvalidNumberArguments;
    }

    try kvs.configSet(tokens[4], tokens[6]);

    // kvs.iter += 1;
    try std.fmt.format(connection.stream.writer(), "+OK\r\n", .{});
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

test "parseRdbFile" {
    const dump = try std.fs.cwd().openFile("dump.rdb", .{ .mode = .read_only });
    defer dump.close();

    const stat = try dump.stat();

    const header = try std.posix.mmap(null, stat.size, std.posix.PROT.READ, std.posix.MAP{ .TYPE = .SHARED }, dump.handle, 0);
    // allocate enough for the header only

    const magic = header[0..5];
    std.debug.print("\nHeader: '{s}'\n", .{magic});
    const version = header[5..9];
    std.debug.print("Version Number: '{s}'\n", .{version});

    std.debug.print("Auxiliary {X}: ", .{header[9]});
    var pivot = try readAuxiliaryBlock(header[10..]);
    pivot += 10;

    std.debug.print("Auxiliary {X}: ", .{header[pivot]});
    pivot += 1;
    pivot += try readAuxiliaryBlock(header[pivot..]);

    std.debug.print("Auxiliary {X}: ", .{header[pivot]});
    pivot += 1;
    pivot += try readAuxiliaryBlock(header[pivot..]);

    std.debug.print("Auxiliary {X}: ", .{header[pivot]});
    pivot += 1;
    pivot += try readAuxiliaryBlock(header[pivot..]);

    std.debug.print("Auxiliary {X}: ", .{header[pivot]});
    pivot += 1;
    pivot += try readAuxiliaryBlock(header[pivot..]);

    // std.debug.print("Database selector: {X}\n", .{header[pivot]});
    // pivot += 1;
    // std.debug.print("Db number {d}\n", .{header[pivot]});
    // pivot += 1;
    // std.debug.print("ResizeDb field {d}\n", .{header[pivot]});

    // const a = [_]u8{ le, header[bitPos + 1] };
    // _ = try std.fmt.parseInt(u16, &a, 10);
    // std.debug.print("Bit: '{} {}\n", .{ le, header[bitPos + 1] });
    // std.debug.print("{d}\n", .{std.fmt.parseInt(i16,&{le,header[bitPos+1]}) });
}

fn readAuxiliaryBlock(buf: []u8) !usize {
    var key1: []u8 = undefined;
    var n = try stringEncoding(buf, &key1);
    std.debug.print("{s} -> ", .{key1});
    var pivot: usize = n;

    var value1: []u8 = undefined;
    n = try stringEncoding(buf[pivot..], &value1);
    pivot += n;
    std.debug.print("'{s}'\n", .{value1});

    return pivot;
}

const Length = enum {
    Next6BitsAreLength,
    AddByteForLength,
    Next4BytesAreLength,
    Special,
    Unknown,
};

fn stringEncoding(buf: []u8, str: *[]u8) !usize {
    const firstTwo = buf[0] & 0b11000000;
    const length = redisLengthEncoding(firstTwo);
    return switch (length) {
        Length.Next6BitsAreLength => {
            const n = buf[0];
            str.* = buf[1 .. 1 + n];
            return n + 1;
        },
        Length.AddByteForLength => {
            std.debug.print("One byte more is length {d}\n", .{buf[0..2]});
            const n = try std.fmt.parseInt(u8, buf[0..2], 10);
            std.debug.print("{}\n", .{n});
            str.* = buf[2 .. 2 + n];
            return n + 3;
        },
        Length.Next4BytesAreLength => {
            std.debug.print("Next 4 bytes are length\n", .{});
            str.* = buf[4..8];
            return 6;
        },
        Length.Special => {
            const last6 = buf[0] & 0b00111111;
            switch (last6) {
                0 => {
                    var tmp: [8]u8 = undefined;
                    const res = try std.fmt.bufPrint(&tmp, "{d}", .{buf[1]});
                    str.* = res;
                    return 2;
                },
                1 => {
                    std.debug.print("1\n", .{});
                    const n: u8 = buf[1];
                    var tmp: [8]u8 = undefined;
                    const res = try std.fmt.bufPrint(&tmp, "{d}", .{n});
                    str.* = res[0..2];
                    return 2;
                },
                2 => {
                    const n = std.mem.readInt(u32, buf[1..5], .big);
                    var tmp: [32]u8 = undefined;
                    const res = try std.fmt.bufPrint(&tmp, "{d}", .{n});
                    str.* = res;
                    return 5;
                },
                3 => {
                    const n = try std.fmt.parseInt(u8, buf[1..9], 10);
                    str.* = buf[9 .. 9 + n];
                    return n + 9;
                },
                else => return error.UnexpectedSpecial,
            }
            return 0;
        },
        Length.Unknown => {
            std.debug.print("Unknown\n", .{});
            return 0;
        },
    };
}

fn redisLengthEncoding(byte: u8) Length {
    const firstTwo = byte & 0b11000000;
    return switch (firstTwo) {
        0b00000000 => Length.Next6BitsAreLength,
        0b01000000 => Length.AddByteForLength,
        0b10000000 => Length.Next4BytesAreLength,
        0b11000000 => Length.Special,
        else => Length.Unknown,
    };
}
