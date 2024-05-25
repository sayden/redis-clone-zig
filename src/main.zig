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
};

const CommandEnd = "\n";
const TokenSplit = "\r\n";

const KvArray = struct {
    hashmap: std.StringHashMap([]u8),
    expiries: std.StringHashMap(i64),
    alloc: std.mem.Allocator,
    mutex: Mutex = Mutex{},
    const Errors = error{NotFound};

    pub fn init(alloc: std.mem.Allocator) KvArray {
        return KvArray{
            .hashmap = std.StringHashMap([]u8).init(alloc),
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

    pub fn get(self: *KvArray, key: []u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const value = self.hashmap.get(key) orelse {
            return KvArray.Errors.NotFound;
        };

        return value;
    }
};

pub fn expiryThread(kvs: *KvArray) !void {
    defer std.debug.print("'Expiry checks' thread finished\n", .{});

    while (true) {
        std.time.sleep(1000000000);

        quit.mutex.lock();
        if (quit.quit) {
            quit.mutex.unlock();
            return;
        }
        quit.mutex.unlock();

        var iter = kvs.expiries.iterator();

        kvs.mutex.lock();
        while (iter.next()) |entry| {
            const now = std.time.milliTimestamp();
            if (entry.value_ptr.* <= now) {
                _ = kvs.hashmap.remove(entry.key_ptr.*);
                _ = kvs.expiries.remove(entry.key_ptr.*);
            }
        }
        kvs.mutex.unlock();
    }
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
    defer chechMemoryLeak(&gpa);
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    const alloc = arena.allocator();
    defer arena.deinit();

    var kvs = KvArray.init(alloc);
    defer kvs.deinit();

    var thread = try std.Thread.spawn(.{}, expiryThread, .{&kvs});
    defer thread.join();

    while (true) {
        quit.mutex.lock();
        if (quit.quit) {
            std.debug.print("Shutting down\n", .{});
            quit.mutex.unlock();
            break;
        }
        quit.mutex.unlock();

        if (listener.accept()) |connection| {
            var t = try std.Thread.spawn(.{}, handle, .{ connection, &kvs });
            t.detach();
        } else |_| {
            std.time.sleep(1000000);
        }
    }
}

fn chechMemoryLeak(gpa: *std.heap.GeneralPurposeAllocator(.{})) void {
    const res = gpa.deinit();
    switch (res) {
        std.heap.Check.ok => {},
        std.heap.Check.leak => std.debug.print("Memory leak detected\n", .{}),
    }
}

const Quit = struct {
    mutex: Mutex = Mutex{},
    quit: bool = false,
};

const Errors = error{InvalidCharacter};
var quit = Quit{};

fn handle(connection: net.Server.Connection, kvs: *KvArray) !void {
    const conReader = connection.stream.reader();

    var buffer: [1024]u8 = undefined;
    var tokens: [128][]u8 = undefined;
    var commands: [32]?[]u8 = undefined;
    for (0..commands.len) |i| {
        commands[i] = null;
    }

    while (true) {
        if (try conReader.read(&buffer) > 0) {
            try splitCommands(&buffer, &commands);
            for (commands) |command| {
                if (command) |cmd| {
                    const n = try parseTokens(cmd, &tokens);
                    try handleCommand(&tokens, n, connection, kvs);
                } else {
                    break;
                }
            }
        }
    }
}

fn splitCommands(buf: []u8, commands: *[32]?[]u8) !void {
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

fn handleCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    switch (getCommands(tokens, n)) {
        Commands.PING => try connection.stream.writeAll("+PONG\r\n"),
        Commands.ECHO => try echoCommand(tokens, n, connection),
        Commands.SET => try setCommand(tokens, n, connection, kvs),
        Commands.GET => try getCommand(tokens, n, connection, kvs),
        Commands.SET_EXPIRY => try setCommand(tokens, n, connection, kvs),
        Commands.QUIT => {
            quit.mutex.lock();
            quit.quit = true;
            connection.stream.close();
            quit.mutex.unlock();
        },
    }
}

fn getCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n != 5) {
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
// *2 $3 SET $3 foo $3 bar
// *2 $3 SET $3 foo $3 bar $2 PX $3 100
//
//  0  1   2  3   4  5   6  7  8  9  10
fn setCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection, kvs: *KvArray) !void {
    if (n < 7) {
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

fn toUpper(s: []u8) void {
    for (s, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') {
            s[i] -= 32;
        }
    }
}

fn echoCommand(tokens: *[128][]u8, n: usize, connection: net.Server.Connection) !void {
    if (n != 5) {
        return error.Invalid;
    }

    try std.fmt.format(connection.stream.writer(), "${d}\r\n{s}\r\n", .{ tokens[4].len, tokens[4] });
}

fn getCommands(tokens: *[128][]u8, _: usize) Commands {
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
    }

    return Commands.PING;
}

fn parseTokens(bytes: []u8, tokens: *[128][]u8) !usize {
    var left: usize = 0;
    var tokenCount: usize = 0;

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

    return tokenCount;
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
    var bytes: [32]u8 = undefined;
    const msg = "hello\r\nworld\r\n";
    @memcpy(bytes[0..msg.len], msg);
    _ = try parseTokens(&bytes, &tokens);

    try std.testing.expectEqualStrings(tokens[0], "hello");
    try std.testing.expectEqualStrings(tokens[1], "world");
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

    _ = try splitCommands(&buffer, &commands);

    try std.testing.expectEqualSlices(u8, "*1\r\n$9\r\nPING", commands[0].?);
    try std.testing.expectEqualSlices(u8, "PING\r\n", commands[1].?[0..6]);
 
    try std.testing.expect(commands[2] == null);
}
