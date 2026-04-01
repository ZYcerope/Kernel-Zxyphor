// =============================================================================
// Kernel Zxyphor - Intrusive Doubly-Linked List
// =============================================================================
// Generic intrusive linked list implementation used throughout the kernel
// for run queues, wait queues, VMA lists, timer lists, etc.
//
// "Intrusive" means the list node is embedded within the data structure
// itself, eliminating the need for separate allocation. This is the
// dominant pattern in kernel code (Linux uses the same approach).
//
// Usage:
//     const MyStruct = struct {
//         data: u32,
//         list_node: List.Node = .{},
//     };
//     var my_list = List.init();
//     my_list.append(&item.list_node);
// =============================================================================

// =============================================================================
// List Node (embedded in each element)
// =============================================================================
pub const Node = struct {
    prev: ?*Node = null,
    next: ?*Node = null,

    /// Remove this node from whatever list it's in
    pub fn remove(self: *Node) void {
        if (self.prev) |p| p.next = self.next;
        if (self.next) |n| n.prev = self.prev;
        self.prev = null;
        self.next = null;
    }

    /// Check if this node is linked into a list
    pub fn isLinked(self: *const Node) bool {
        return self.prev != null or self.next != null;
    }
};

// =============================================================================
// Doubly-Linked List (circular sentinel style)
// =============================================================================
pub const List = struct {
    head: ?*Node = null,
    tail: ?*Node = null,
    len: usize = 0,

    pub fn init() List {
        return List{};
    }

    /// Add a node to the end of the list
    pub fn append(self: *List, node: *Node) void {
        node.next = null;
        node.prev = self.tail;
        if (self.tail) |t| {
            t.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
        self.len += 1;
    }

    /// Add a node to the beginning of the list
    pub fn prepend(self: *List, node: *Node) void {
        node.prev = null;
        node.next = self.head;
        if (self.head) |h| {
            h.prev = node;
        } else {
            self.tail = node;
        }
        self.head = node;
        self.len += 1;
    }

    /// Insert a node after a specific node
    pub fn insertAfter(self: *List, target: *Node, node: *Node) void {
        node.prev = target;
        node.next = target.next;
        if (target.next) |n| {
            n.prev = node;
        } else {
            self.tail = node;
        }
        target.next = node;
        self.len += 1;
    }

    /// Insert a node before a specific node
    pub fn insertBefore(self: *List, target: *Node, node: *Node) void {
        node.next = target;
        node.prev = target.prev;
        if (target.prev) |p| {
            p.next = node;
        } else {
            self.head = node;
        }
        target.prev = node;
        self.len += 1;
    }

    /// Remove a specific node from the list
    pub fn remove(self: *List, node: *Node) void {
        if (node.prev) |p| {
            p.next = node.next;
        } else {
            self.head = node.next;
        }

        if (node.next) |n| {
            n.prev = node.prev;
        } else {
            self.tail = node.prev;
        }

        node.prev = null;
        node.next = null;
        self.len -= 1;
    }

    /// Remove and return the first node
    pub fn popFront(self: *List) ?*Node {
        const node = self.head orelse return null;
        self.remove(node);
        return node;
    }

    /// Remove and return the last node
    pub fn popBack(self: *List) ?*Node {
        const node = self.tail orelse return null;
        self.remove(node);
        return node;
    }

    /// Get the first node without removing
    pub fn first(self: *const List) ?*Node {
        return self.head;
    }

    /// Get the last node without removing
    pub fn last(self: *const List) ?*Node {
        return self.tail;
    }

    /// Check if list is empty
    pub fn isEmpty(self: *const List) bool {
        return self.head == null;
    }

    /// Get the length of the list
    pub fn length(self: *const List) usize {
        return self.len;
    }

    /// Move all nodes from another list to the end of this list
    pub fn spliceBack(self: *List, other: *List) void {
        if (other.head == null) return;

        if (self.tail) |t| {
            t.next = other.head;
            other.head.?.prev = t;
        } else {
            self.head = other.head;
        }
        self.tail = other.tail;
        self.len += other.len;

        other.head = null;
        other.tail = null;
        other.len = 0;
    }

    // =========================================================================
    // Iterator
    // =========================================================================
    pub const Iterator = struct {
        current: ?*Node,

        pub fn next(self: *Iterator) ?*Node {
            const node = self.current orelse return null;
            self.current = node.next;
            return node;
        }
    };

    pub const ReverseIterator = struct {
        current: ?*Node,

        pub fn next(self: *ReverseIterator) ?*Node {
            const node = self.current orelse return null;
            self.current = node.prev;
            return node;
        }
    };

    /// Forward iterator
    pub fn iterator(self: *const List) Iterator {
        return Iterator{ .current = self.head };
    }

    /// Reverse iterator
    pub fn reverseIterator(self: *const List) ReverseIterator {
        return ReverseIterator{ .current = self.tail };
    }
};

// =============================================================================
// Helper: Get containing structure from a node pointer
// (Zig equivalent of Linux's container_of / list_entry)
// =============================================================================
pub fn nodeToParent(comptime T: type, comptime field_name: []const u8, node: *Node) *T {
    const offset = @offsetOf(T, field_name);
    const node_addr = @intFromPtr(node);
    const parent_addr = node_addr - offset;
    return @ptrFromInt(parent_addr);
}

pub fn nodeToParentConst(comptime T: type, comptime field_name: []const u8, node: *const Node) *const T {
    const offset = @offsetOf(T, field_name);
    const node_addr = @intFromPtr(node);
    const parent_addr = node_addr - offset;
    return @ptrFromInt(parent_addr);
}

// =============================================================================
// Singly-Linked List (for stack-like usage, simpler and slightly faster)
// =============================================================================
pub const SNode = struct {
    next: ?*SNode = null,
};

pub const SList = struct {
    head: ?*SNode = null,
    len: usize = 0,

    pub fn init() SList {
        return SList{};
    }

    /// Push to front
    pub fn push(self: *SList, node: *SNode) void {
        node.next = self.head;
        self.head = node;
        self.len += 1;
    }

    /// Pop from front
    pub fn pop(self: *SList) ?*SNode {
        const node = self.head orelse return null;
        self.head = node.next;
        node.next = null;
        self.len -= 1;
        return node;
    }

    pub fn isEmpty(self: *const SList) bool {
        return self.head == null;
    }

    pub fn length(self: *const SList) usize {
        return self.len;
    }
};
